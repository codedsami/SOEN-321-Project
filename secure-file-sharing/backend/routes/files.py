from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from cryptography.exceptions import InvalidTag
from models import db, User, File, Share
from crypto import (
    load_public_key_from_pem,
    wrap_fek, generate_fek,
    encrypt_file, hash_file,
    decrypt_private_key,
    unwrap_fek, decrypt_file,
    verify_file_integrity,
)
import io

files_bp = Blueprint('files', __name__)

SUPPORTED_ENC_ALGOS = {'aes-256-gcm', 'chacha20-poly1305'}
SUPPORTED_HASH_ALGOS = {'sha256', 'sha512', 'md5'}


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
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'error': 'No file provided'}), 400
    if uploaded.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    enc_algo  = request.form.get('enc_algo', 'aes-256-gcm').lower()
    hash_algo = request.form.get('hash_algo', 'sha256').lower()

    if enc_algo not in SUPPORTED_ENC_ALGOS:
        return jsonify({'error': f'Unsupported enc_algo: {enc_algo}'}), 400
    if hash_algo not in SUPPORTED_HASH_ALGOS:
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

    response = file_record.to_dict()
    if hash_algo == 'md5':
        response['warning'] = 'MD5 is cryptographically broken and should not be used for security purposes'

    return jsonify(response), 201


# ============================================================
#  DOWNLOAD — POST /files/<id>/download
#  Requires password in JSON body to unlock the private key.
#  Full security chain:
#    1. Verify JWT and ownership / share access
#    2. Fetch user's encrypted RSA private key from DB
#    3. Re-derive AES key via PBKDF2(password, stored salt)
#    4. Decrypt RSA private key blob with AES-256-GCM (unmarshal)
#    5. Unwrap FEK using RSA-OAEP with decrypted private key
#    6. Decrypt file ciphertext (AES-256-GCM or ChaCha20-Poly1305)
#    7. Recompute hash of decrypted plaintext
#    8. Compare recomputed hash vs stored hash
#    9. Return file + integrity result; 422 on mismatch
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
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

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

    # Step 5 — unwrap the FEK using RSA-OAEP with the decrypted private key
    try:
        fek = unwrap_fek(wrapped_fek, private_key)
    except Exception:
        return jsonify({'error': 'Failed to unwrap file encryption key'}), 500

    # Step 6 — decrypt file ciphertext with FEK (AES-256-GCM or ChaCha20-Poly1305)
    try:
        plaintext = decrypt_file(
            file_record.ciphertext,
            file_record.enc_algo,
            fek,
            file_record.nonce,
        )
    except InvalidTag:
        return jsonify({
            'error': 'Decryption failed — authentication tag mismatch',
            'integrity': False,
        }), 422
    except Exception as e:
        return jsonify({'error': f'Decryption error: {str(e)}'}), 500

    # Step 7-8 — recompute hash of decrypted plaintext and compare to stored value
    recomputed_hash = hash_file(plaintext, file_record.hash_algo)
    integrity_ok    = verify_file_integrity(plaintext, file_record.file_hash, file_record.hash_algo)

    # Step 9 — integrity result: abort with detail if mismatch, else send file
    if not integrity_ok:
        return jsonify({
            'error':           'Integrity check FAILED — file has been tampered with',
            'integrity':       False,
            'hash_algo':       file_record.hash_algo,
            'stored_hash':     file_record.file_hash,
            'recomputed_hash': recomputed_hash,
        }), 422

    response = send_file(
        io.BytesIO(plaintext),
        download_name=file_record.filename,
        as_attachment=True,
        mimetype='application/octet-stream',
    )
    # Integrity metadata surfaced in response headers for the client to inspect
    response.headers['X-Integrity-Check'] = 'PASS'
    response.headers['X-Hash-Algorithm']  = file_record.hash_algo
    response.headers['X-File-Hash']       = file_record.file_hash
    return response
