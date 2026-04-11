from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, File
from crypto import (
    generate_fek, encrypt_file, hash_file,
    wrap_fek, load_public_key_from_pem
)

files_bp = Blueprint('files', __name__)

SUPPORTED_ENC_ALGOS = {'aes-256-gcm', 'chacha20-poly1305'}
SUPPORTED_HASH_ALGOS = {'sha256', 'sha512', 'md5'}


@files_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get the uploaded file
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    uploaded = request.files['file']
    if uploaded.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    plaintext = uploaded.read()

    # Algorithm selection (defaults: aes-256-gcm, sha256)
    enc_algo = request.form.get('enc_algo', 'aes-256-gcm').lower()
    hash_algo = request.form.get('hash_algo', 'sha256').lower()

    if enc_algo not in SUPPORTED_ENC_ALGOS:
        return jsonify({'error': f'Unsupported encryption algorithm: {enc_algo}'}), 400
    if hash_algo not in SUPPORTED_HASH_ALGOS:
        return jsonify({'error': f'Unsupported hash algorithm: {hash_algo}'}), 400

    # 1. Hash plaintext BEFORE encryption
    file_hash = hash_file(plaintext, hash_algo)

    # 2. Generate random FEK and encrypt file
    fek = generate_fek()
    ciphertext, nonce = encrypt_file(plaintext, enc_algo, fek)

    # 3. Wrap FEK with owner's RSA public key
    public_key = load_public_key_from_pem(user.public_key_pem.encode() if isinstance(user.public_key_pem, str) else user.public_key_pem)
    wrapped_fek = wrap_fek(fek, public_key)

    # 4. Store in DB
    file_record = File(
        owner_id=user.id,
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

    response = {
        'message': 'File uploaded and encrypted successfully',
        'file': file_record.to_dict(),
        'encryption_details': {
            'algorithm': enc_algo,
            'hash_algorithm': hash_algo,
            'file_hash': file_hash,
        },
    }

    if hash_algo == 'md5':
        response['encryption_details']['warning'] = 'MD5 is cryptographically broken and should not be used for security purposes'

    return jsonify(response), 201
