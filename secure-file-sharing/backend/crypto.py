import os
import hashlib
import bcrypt

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


# ============================================================
#  1. PASSWORD HASHING — bcrypt
#  Used for: storing user passwords securely at registration
#  Why bcrypt: intentionally slow (cost factor 12 = ~300ms per
#  attempt), salted automatically, brute-force resistant.
#  Unlike SHA-256 (fast, no salt), bcrypt is designed for passwords.
# ============================================================

def hash_password(password: str) -> bytes:
    """
    Hash a plaintext password using bcrypt.
    bcrypt automatically generates and embeds a random salt.
    Returns the full hash bytes to store in the DB.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))


def verify_password(password: str, stored_hash: bytes) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    Returns True if valid, False otherwise.
    Safe against timing attacks — bcrypt.checkpw is constant-time.
    """
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)


# ============================================================
#  2. KEY DERIVATION — PBKDF2
#  Used for: deriving an AES key from a user password to
#  encrypt/decrypt the RSA private key stored in the DB.
#  Why PBKDF2: adds iterations (100,000) to slow brute-force,
#  and a random salt to prevent rainbow table attacks.
# ============================================================

def derive_key_from_password(password: str, salt: bytes = None):
    """
    Derive a 256-bit AES key from a user password using PBKDF2-HMAC-SHA256.
    If no salt is provided, generate a new random 16-byte salt.
    Returns (derived_key_bytes, salt) — store the salt alongside the encrypted key.
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256-bit key
        salt=salt,
        iterations=100_000,  # NIST recommended minimum
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


# ============================================================
#  3. RSA KEY PAIR GENERATION + MARSHAL / UNMARSHAL
#  Used for: generating a key pair per user at registration.
#  Public key  → stored in DB as plain PEM (safe to expose).
#  Private key → encrypted with AES key derived from password,
#                stored as an encrypted blob in DB.
#  Why RSA-2048: widely supported, sufficient security for
#  key wrapping. OAEP padding prevents padding oracle attacks.
# ============================================================

def generate_rsa_keypair():
    """
    Generate a 2048-bit RSA key pair.
    Returns (private_key_object, public_key_object).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """
    Serialize RSA public key to PEM format for storage in DB.
    Public keys are stored unencrypted — they are public by design.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def encrypt_private_key(private_key, password: str):
    """
    Serialize and encrypt the RSA private key using a password.
    Steps:
      1. Derive AES-256 key from password using PBKDF2
      2. Encrypt the private key PEM using AES-256-GCM
      3. Return (encrypted_blob, salt, nonce) — all stored in DB
    The raw private key is never stored — only this encrypted blob.
    """
    # Derive AES key from password
    aes_key, salt = derive_key_from_password(password)

    # Serialize private key to PEM bytes
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # we encrypt manually below
    )

    # Encrypt PEM using AES-256-GCM
    nonce = os.urandom(12)  # 96-bit nonce — fresh per encryption
    aesgcm = AESGCM(aes_key)
    encrypted_blob = aesgcm.encrypt(nonce, private_key_pem, None)

    return encrypted_blob, salt, nonce


def decrypt_private_key(encrypted_blob: bytes, salt: bytes, nonce: bytes, password: str):
    """
    Decrypt an encrypted RSA private key blob using a password.
    Steps:
      1. Re-derive AES key from password + stored salt (PBKDF2)
      2. Decrypt blob using AES-256-GCM + stored nonce
      3. Deserialize PEM bytes back to RSA private key object
    Returns the RSA private key object ready for use.
    """
    aes_key, _ = derive_key_from_password(password, salt=salt)
    aesgcm = AESGCM(aes_key)
    private_key_pem = aesgcm.decrypt(nonce, encrypted_blob, None)

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    return private_key


def load_public_key_from_pem(public_key_pem: bytes):
    """
    Deserialize a PEM-encoded public key back to an RSA key object.
    Used when fetching a recipient's public key from the DB.
    """
    return serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )


# ============================================================
#  4. RSA KEY WRAPPING — wrap / unwrap the FEK
#  Used for: encrypting the File Encryption Key (FEK) with
#  a user's RSA public key so only they can decrypt it.
#  Why OAEP: probabilistic padding — same plaintext produces
#  different ciphertext each time. Prevents chosen-ciphertext
#  attacks. PKCS#1 v1.5 is vulnerable (padding oracle attack).
# ============================================================

def wrap_fek(fek: bytes, public_key) -> bytes:
    """
    Encrypt (wrap) a File Encryption Key using RSA-OAEP.
    The FEK is a 32-byte AES key — well within RSA-2048 limits.
    Returns the wrapped FEK bytes to store in the DB.
    """
    wrapped = public_key.encrypt(
        fek,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped


def unwrap_fek(wrapped_fek: bytes, private_key) -> bytes:
    """
    Decrypt (unwrap) a File Encryption Key using RSA private key.
    Returns the raw 32-byte FEK for use in AES/ChaCha decryption.
    """
    fek = private_key.decrypt(
        wrapped_fek,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return fek


# ============================================================
#  5. FILE ENCRYPTION — AES-256-GCM
#  Used for: encrypting file contents before upload.
#  Why AES-256-GCM: AEAD — provides confidentiality AND an
#  authentication tag in one operation. No separate HMAC needed.
#  The auth tag detects ciphertext tampering on decryption.
#  Why not CBC: CBC requires separate MAC (HMAC), vulnerable
#  to padding oracle attacks without careful implementation.
# ============================================================

def encrypt_aes_gcm(plaintext: bytes, fek: bytes):
    """
    Encrypt file bytes using AES-256-GCM.
    - Generates a fresh 96-bit nonce per encryption (never reuse)
    - Returns (ciphertext_with_tag, nonce)
    - The 16-byte auth tag is appended to ciphertext automatically
    WARNING: Never reuse the same (key, nonce) pair — doing so
    completely breaks AES-GCM confidentiality and integrity.
    """
    nonce = os.urandom(12)  # 96-bit — NIST recommended for GCM
    aesgcm = AESGCM(fek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes auth tag
    return ciphertext, nonce


def decrypt_aes_gcm(ciphertext: bytes, fek: bytes, nonce: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and verify the auth tag.
    Raises InvalidTag exception if the ciphertext was tampered with.
    This provides authenticated decryption — integrity is verified
    automatically before any plaintext is returned.
    """
    aesgcm = AESGCM(fek)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


# ============================================================
#  6. FILE ENCRYPTION — ChaCha20-Poly1305
#  Used for: alternative symmetric encryption algorithm.
#  Why ChaCha20: modern stream cipher, AEAD like AES-GCM,
#  used in TLS 1.3. Faster on devices without hardware AES
#  acceleration (mobile, embedded). No timing side-channels.
# ============================================================

def encrypt_chacha20(plaintext: bytes, fek: bytes):
    """
    Encrypt file bytes using ChaCha20-Poly1305.
    - Generates a fresh 96-bit nonce per encryption
    - Returns (ciphertext_with_tag, nonce)
    - Poly1305 auth tag provides integrity (like GCM auth tag)
    """
    nonce = os.urandom(12)  # 96-bit nonce
    chacha = ChaCha20Poly1305(fek)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_chacha20(ciphertext: bytes, fek: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ChaCha20-Poly1305 ciphertext and verify Poly1305 tag.
    Raises InvalidTag if tampered. Same integrity guarantee as AES-GCM.
    """
    chacha = ChaCha20Poly1305(fek)
    plaintext = chacha.decrypt(nonce, ciphertext, None)
    return plaintext


# ============================================================
#  7. RSA DIRECT ENCRYPTION (small files only)
#  Used for: demonstrating asymmetric encryption directly on data.
#  Limitation: RSA-2048 with OAEP can only encrypt ~190 bytes max.
#  In practice: only used for tiny files or demo purposes.
#  Real systems always use hybrid encryption (RSA + AES).
# ============================================================

def encrypt_rsa(plaintext: bytes, public_key) -> bytes:
    """
    Encrypt data directly using RSA-OAEP.
    WARNING: Maximum plaintext size for RSA-2048 with OAEP is
    190 bytes. Use hybrid encryption (AES + RSA key wrap) for
    anything larger. This function is for demo/small files only.
    """
    return public_key.encrypt(
        plaintext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_rsa(ciphertext: bytes, private_key) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext using private key.
    """
    return private_key.decrypt(
        ciphertext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ============================================================
#  8. FILE HASHING — SHA-256, SHA-512, MD5
#  Used for: computing a digest of the plaintext file BEFORE
#  encryption. Stored in DB. Recomputed after decryption and
#  compared to verify file integrity (our "hash proof").
#  Why hash before encrypt: so we're always comparing digests
#  of the original plaintext, not the ciphertext.
#  MD5: included as a NEGATIVE EXAMPLE — broken algorithm,
#  collisions can be computed in seconds on modern hardware.
# ============================================================

def hash_file(file_bytes: bytes, algorithm: str) -> str:
    """
    Compute a cryptographic hash of file bytes.
    Supported algorithms: 'sha256', 'sha512', 'md5'
    Returns hex digest string for storage in DB.

    Security note:
    - SHA-256: secure, collision resistant, recommended
    - SHA-512: secure, stronger, larger digest (64 bytes)
    - MD5: BROKEN — collisions found, do not use in production.
            Included here only to demonstrate a weak algorithm.
    """
    algorithm = algorithm.lower()

    if algorithm == 'sha256':
        return hashlib.sha256(file_bytes).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(file_bytes).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(file_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def hash_file_all(file_bytes: bytes) -> dict:
    """
    Compute all three hash digests at once for the demo panel (US-13).
    Returns a dict with all three digests so the user can compare
    output lengths and formats side by side.
    """
    return {
        'sha256': hashlib.sha256(file_bytes).hexdigest(),   # 64 hex chars
        'sha512': hashlib.sha512(file_bytes).hexdigest(),   # 128 hex chars
        'md5':    hashlib.md5(file_bytes).hexdigest(),      # 32 hex chars — broken
    }


def verify_file_integrity(file_bytes: bytes, stored_hash: str, algorithm: str) -> bool:
    """
    Recompute the hash of decrypted file bytes and compare to stored hash.
    Returns True if hashes match (file intact), False if they differ (tampered).
    This is the core integrity proof — US-11 and US-12 in user stories.
    """
    recomputed = hash_file(file_bytes, algorithm)
    return recomputed == stored_hash


# ============================================================
#  9. UNIFIED ENCRYPT / DECRYPT — algorithm selector
#  Convenience wrappers that accept an algorithm name string
#  and route to the correct function. Used by the upload and
#  download routes so they don't need to import individually.
# ============================================================

def generate_fek() -> bytes:
    """
    Generate a random 256-bit File Encryption Key using os.urandom.
    os.urandom uses the OS CSPRNG — cryptographically secure.
    Never use random.randbytes() or random.random() for key material.
    """
    return os.urandom(32)  # 256-bit


def encrypt_file(plaintext: bytes, algorithm: str, fek: bytes):
    """
    Encrypt file bytes using the selected algorithm.
    Supported: 'aes-256-gcm', 'chacha20-poly1305', 'rsa-oaep'
    Returns (ciphertext, nonce) — nonce is None for RSA direct.
    Note: RSA direct only works for files <= 190 bytes.
    """
    algorithm = algorithm.lower()

    if algorithm == 'aes-256-gcm':
        return encrypt_aes_gcm(plaintext, fek)
    elif algorithm == 'chacha20-poly1305':
        return encrypt_chacha20(plaintext, fek)
    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")


def decrypt_file(ciphertext: bytes, algorithm: str, fek: bytes, nonce: bytes) -> bytes:
    """
    Decrypt file bytes using the selected algorithm.
    Supported: 'aes-256-gcm', 'chacha20-poly1305'
    Raises InvalidTag if auth tag verification fails (tampered ciphertext).
    """
    algorithm = algorithm.lower()

    if algorithm == 'aes-256-gcm':
        return decrypt_aes_gcm(ciphertext, fek, nonce)
    elif algorithm == 'chacha20-poly1305':
        return decrypt_chacha20(ciphertext, fek, nonce)
    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")