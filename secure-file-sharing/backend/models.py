from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


# ============================================================
#  USER MODEL
#  Stores account credentials and RSA key material.
#
#  Security design:
#  - password is NEVER stored — only the bcrypt hash
#  - public_key_pem stored in plain PEM (public by design)
#  - private_key_enc stored as AES-256-GCM encrypted blob
#  - private_key_salt + private_key_nonce needed to re-derive
#    the AES key (PBKDF2) and decrypt the private key blob
#    on login
# ============================================================

class User(db.Model):
    __tablename__ = 'users'

    id                = db.Column(db.Integer, primary_key=True)
    email             = db.Column(db.String(255), unique=True, nullable=False)

    # bcrypt hash of the user's password — never store plaintext
    password_hash     = db.Column(db.LargeBinary, nullable=False)

    # RSA public key — stored as plain PEM, safe to expose
    public_key_pem    = db.Column(db.Text, nullable=False)

    # RSA private key — stored as AES-256-GCM encrypted blob
    # Encrypted using a key derived from the user's password (PBKDF2)
    private_key_enc   = db.Column(db.LargeBinary, nullable=False)

    # Salt used in PBKDF2 to derive the AES key for private key encryption
    # Must be stored alongside the encrypted blob to re-derive the key on login
    private_key_salt  = db.Column(db.LargeBinary, nullable=False)

    # Nonce used in AES-256-GCM encryption of the private key
    # Must be stored to decrypt the private key blob on login
    private_key_nonce = db.Column(db.LargeBinary, nullable=False)

    created_at        = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    files             = db.relationship('File', backref='owner', lazy=True,
                                        foreign_keys='File.owner_id')
    shares_sent       = db.relationship('Share', backref='shared_by', lazy=True,
                                        foreign_keys='Share.owner_id')
    shares_received   = db.relationship('Share', backref='recipient', lazy=True,
                                        foreign_keys='Share.recipient_id')

    def to_dict(self):
        """Return safe user data — never include password_hash or key blobs."""
        return {
            'id':         self.id,
            'email':      self.email,
            'created_at': self.created_at.isoformat()
        }

    def __repr__(self):
        return f'<User {self.email}>'


# ============================================================
#  FILE MODEL
#  Stores encrypted file data and all associated crypto metadata.
#
#  Security design (zero-knowledge server):
#  - ciphertext      : encrypted file bytes — server never sees plaintext
#  - wrapped_fek     : AES/ChaCha key encrypted with owner's RSA public key
#  - nonce           : random IV used during encryption — needed to decrypt
#  - file_hash       : SHA-256/SHA-512/MD5 digest of the PLAINTEXT file
#                      computed BEFORE encryption, used for integrity check
#  - enc_algo        : which algorithm was used (aes-256-gcm / chacha20-poly1305)
#  - hash_algo       : which hash algorithm was used (sha256 / sha512 / md5)
#
#  The server stores ONLY this encrypted data.
#  It cannot decrypt the file without the user's private key.
# ============================================================

class File(db.Model):
    __tablename__ = 'files'

    id           = db.Column(db.Integer, primary_key=True)
    owner_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Original filename — stored as metadata only
    filename     = db.Column(db.String(255), nullable=False)

    # File size in bytes (of the original plaintext)
    file_size    = db.Column(db.Integer, nullable=False)

    # Encrypted file content — AES-GCM or ChaCha20 ciphertext
    # Includes the authentication tag appended at the end
    ciphertext   = db.Column(db.LargeBinary, nullable=False)

    # File Encryption Key (FEK) wrapped with owner's RSA public key
    # Only the owner's RSA private key can unwrap this
    wrapped_fek  = db.Column(db.LargeBinary, nullable=False)

    # Random nonce/IV used during file encryption
    # 96-bit (12 bytes) for both AES-GCM and ChaCha20-Poly1305
    # A fresh nonce is generated per file — never reused
    nonce        = db.Column(db.LargeBinary, nullable=False)

    # Cryptographic hash of the PLAINTEXT file (before encryption)
    # Used to verify file integrity after decryption
    # Hex-encoded digest string
    file_hash    = db.Column(db.String(128), nullable=False)

    # Encryption algorithm used: 'aes-256-gcm' or 'chacha20-poly1305'
    enc_algo     = db.Column(db.String(50), nullable=False)

    # Hash algorithm used: 'sha256', 'sha512', or 'md5'
    hash_algo    = db.Column(db.String(20), nullable=False)

    upload_date  = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    shares       = db.relationship('Share', backref='file', lazy=True,
                                   cascade='all, delete-orphan')

    def to_dict(self):
        """
        Return file metadata safe to send to the client.
        Note: ciphertext and wrapped_fek are NOT included here —
        they are only sent on an explicit download request.
        This is the zero-knowledge listing — metadata only.
        """
        return {
            'id':          self.id,
            'filename':    self.filename,
            'file_size':   self.file_size,
            'file_hash':   self.file_hash,
            'enc_algo':    self.enc_algo,
            'hash_algo':   self.hash_algo,
            'upload_date': self.upload_date.isoformat(),
            'owner_id':    self.owner_id
        }

    def to_download_dict(self):
        """
        Return full encrypted file data for download.
        Only called on an explicit GET /files/{id}/download request
        by the authenticated owner or an authorized recipient.
        All values are base64-encoded for JSON transport.
        """
        return {
            'id':          self.id,
            'filename':    self.filename,
            'ciphertext':  _b64(self.ciphertext),
            'wrapped_fek': _b64(self.wrapped_fek),
            'nonce':       _b64(self.nonce),
            'file_hash':   self.file_hash,
            'enc_algo':    self.enc_algo,
            'hash_algo':   self.hash_algo,
        }

    def __repr__(self):
        return f'<File {self.filename} owner={self.owner_id}>'


# ============================================================
#  SHARE MODEL
#  Stores one record per (file, recipient) pair.
#
#  Key design — each recipient gets their OWN wrapped FEK:
#  - The file is encrypted ONCE (one ciphertext in File table)
#  - For each recipient, the FEK is re-wrapped with THEIR
#    RSA public key and stored here
#  - The recipient uses their RSA private key to unwrap the
#    FEK and decrypt the file
#
#  Security: the server stores wrapped FEKs for each recipient
#  but cannot unwrap any of them — it doesn't have private keys.
#  This is the zero-knowledge sharing model.
# ============================================================

class Share(db.Model):
    __tablename__ = 'shares'

    id           = db.Column(db.Integer, primary_key=True)

    # The file being shared
    file_id      = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)

    # The user who owns the file and initiated the share
    owner_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # The user the file is shared with
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # FEK re-wrapped with the RECIPIENT's RSA public key
    # The recipient unwraps this with their own RSA private key
    # to get the FEK and decrypt the file
    wrapped_fek  = db.Column(db.LargeBinary, nullable=False)

    shared_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':           self.id,
            'file_id':      self.file_id,
            'owner_id':     self.owner_id,
            'recipient_id': self.recipient_id,
            'wrapped_fek':  _b64(self.wrapped_fek),
            'shared_at':    self.shared_at.isoformat()
        }

    def __repr__(self):
        return f'<Share file={self.file_id} recipient={self.recipient_id}>'


# ============================================================
#  HELPER
# ============================================================

import base64

def _b64(data: bytes) -> str:
    """Encode bytes to base64 string for safe JSON transport."""
    return base64.b64encode(data).decode('utf-8') if data else None


def b64_decode(data: str) -> bytes:
    """Decode base64 string back to bytes. Used in routes when receiving data."""
    return base64.b64decode(data) if data else None