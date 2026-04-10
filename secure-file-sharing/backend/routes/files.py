from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, File, Share
from crypto import (
    load_public_key_from_pem,
    wrap_fek, generate_fek,
    encrypt_file, hash_file,
    decrypt_private_key,
)

files_bp = Blueprint('files', __name__)


# ============================================================
#  LIST FILES — GET /files
# ============================================================
@files_bp.route('/files', methods=['GET'])
@jwt_required()
def list_files():
    user_id = int(get_jwt_identity())
    files = File.query.filter_by(owner_id=user_id).all()
    return jsonify([f.to_dict() for f in files]), 200


# ============================================================
#  UPLOAD — POST /files/upload
#  1. Hash plaintext with selected algorithm (before encryption)
#  2. Generate a fresh random FEK (256-bit, CSPRNG)
#  3. Encrypt file with AES-256-GCM or ChaCha20-Poly1305
#  4. Wrap FEK with owner's RSA public key (RSA-OAEP)
#  5. Store ciphertext, wrapped FEK, nonce, and hash in DB
#  Server never holds plaintext at rest — zero-knowledge design.
# ============================================================
@files_bp.route('/files/upload', methods=['POST'])
@jwt_required()
def upload_file():
    user_id = int(get_jwt_identity())
    user = User.query.get_or_404(user_id)

    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'error': 'No file provided'}), 400

    enc_algo  = request.form.get('enc_algo', 'aes-256-gcm').lower()
    hash_algo = request.form.get('hash_algo', 'sha256').lower()

    if enc_algo not in ('aes-256-gcm', 'chacha20-poly1305'):
        return jsonify({'error': f'Unsupported enc_algo: {enc_algo}'}), 400
    if hash_algo not in ('sha256', 'sha512', 'md5'):
        return jsonify({'error': f'Unsupported hash_algo: {hash_algo}'}), 400

    plaintext = uploaded.read()

    # Hash plaintext BEFORE encryption — stored for integrity check on download
    file_hash = hash_file(plaintext, hash_algo)

    # Fresh random FEK per file — never reuse keys
    fek = generate_fek()
    ciphertext, nonce = encrypt_file(plaintext, enc_algo, fek)

    # Wrap FEK with owner's RSA public key — only owner can unwrap with private key
    pem = user.public_key_pem
    if isinstance(pem, str):
        pem = pem.encode()
    public_key  = load_public_key_from_pem(pem)
    wrapped_fek = wrap_fek(fek, public_key)

    file_record = File(
        owner_id=user_id,
        filename=uploaded.filename,
        file_size=len(plaintext),
        ciphertext=ciphertext,
        wrapped_fek=wrapped_fek,
        nonce=nonce,
        file_hash=file_hash,
        enc_algo=enc_algo,
        hash_algo=hash_algo,
    )
    db.session.add(file_record)
    db.session.commit()

    return jsonify(file_record.to_dict()), 201


# ============================================================
#  DOWNLOAD — POST /files/<id>/download
#  Requires password in JSON body to unlock the private key.
#  Steps implemented so far:
#    1. Verify JWT and ownership / share access
#    2. Fetch user's encrypted RSA private key from DB
#    3. Re-derive AES key via PBKDF2(password, stored salt)
#    4. Decrypt RSA private key blob with AES-256-GCM (unmarshal)
# ============================================================
@files_bp.route('/files/<int:file_id>/download', methods=['POST'])
@jwt_required()
def download_file(file_id):
    user_id = int(get_jwt_identity())

    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'error': 'password required in request body'}), 400
    password = data['password']

    # Step 1 — verify file exists and user is authorised
    file_record = File.query.get_or_404(file_id)

    if file_record.owner_id == user_id:
        wrapped_fek = file_record.wrapped_fek
    else:
        share = Share.query.filter_by(file_id=file_id, recipient_id=user_id).first()
        if not share:
            return jsonify({'error': 'Access denied'}), 403
        wrapped_fek = share.wrapped_fek

    # Step 2 — fetch encrypted private key blob from DB
    user = User.query.get_or_404(user_id)

    # Steps 3-4 — re-derive AES key via PBKDF2(password, salt) then
    #             decrypt the RSA private key blob (AES-256-GCM unmarshal)
    try:
        private_key = decrypt_private_key(
            user.private_key_enc,
            user.private_key_salt,
            user.private_key_nonce,
            password,
        )
    except Exception:
        return jsonify({'error': 'Invalid password — cannot decrypt private key'}), 401

    # Placeholder until FEK unwrap + file decryption are added
    return jsonify({'status': 'private_key_decrypted'}), 200
