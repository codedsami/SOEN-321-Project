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
from datetime import datetime, timedelta
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
#  SHARED WITH ME — GET /files/shared-with-me
#  Returns metadata for every file another user has shared with
#  the requesting user.  No ciphertext is returned here.
# ============================================================
@files_bp.route('/files/shared-with-me', methods=['GET'])
@jwt_required()
def shared_with_me():
    user_id = int(get_jwt_identity())
    shares = Share.query.filter_by(recipient_id=user_id).all()
    result = []
    for share in shares:
        f = db.session.get(File, share.file_id)
        if not f:
            continue
        owner = db.session.get(User, f.owner_id)
        result.append({
            'share_id':    share.id,
            'file_id':     f.id,
            'filename':    f.filename,
            'file_size':   f.file_size,
            'owner_email': owner.email if owner else None,
            'enc_algo':    f.enc_algo,
            'hash_algo':   f.hash_algo,
            'file_hash':   f.file_hash,
            'shared_at':   share.shared_at.isoformat(),
            'expires_at':  share.expires_at.isoformat() if share.expires_at else None,
            'can_edit':    share.can_edit,
        })
    return jsonify(result), 200


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
        return jsonify({'ERROR': 'User not found'}), 404

    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'ERROR': 'No file provided'}), 400
    if uploaded.filename == '':
        return jsonify({'ERROR': 'Empty filename'}), 400

    enc_algo  = request.form.get('enc_algo', 'aes-256-gcm').lower()
    hash_algo = request.form.get('hash_algo', 'sha256').lower()

    if enc_algo not in SUPPORTED_ENC_ALGOS:
        return jsonify({'ERROR': f'Unsupported enc_algo: {enc_algo}'}), 400
    if hash_algo not in SUPPORTED_HASH_ALGOS:
        return jsonify({'ERROR': f'Unsupported hash_algo: {hash_algo}'}), 400

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


@files_bp.route('/files/<int:file_id>', methods=['DELETE'])
@jwt_required()
def delete_list(file_id):
    user_id = get_jwt_identity()

    file_record = db.session.get(File, file_id)
    if not file_record:
        return jsonify({'ERROR': 'File not found'}), 404

    if file_record.owner_id != int(user_id):
        return jsonify({'ERROR': 'Forbidden - you do not own this file'}), 403

    db.session.delete(file_record)
    db.session.commit()

    return jsonify({'MESSAGE': f'File {file_id} deleted successfully'}), 200

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
        return jsonify({'ERROR': 'password required in request body'}), 400
    password = data['password']

    # Step 1 — verify file exists and user is authorised
    file_record = File.query.get_or_404(file_id)

    if file_record.owner_id == user_id:
        wrapped_fek = file_record.wrapped_fek
    else:
        share = Share.query.filter_by(file_id=file_id, recipient_id=user_id).first()
        if not share:
            return jsonify({'ERROR': 'Access denied'}), 403
        
        # NEW EXPIRATION CHECK FOR US-6
        if share.expires_at and share.expires_at < datetime.utcnow():
            return jsonify({'ERROR': 'This shared link has expired'}), 403
        
        wrapped_fek = share.wrapped_fek

    # Step 2 — fetch encrypted private key blob from DB
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'ERROR': 'User not found'}), 404

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
        return jsonify({'ERROR': 'Invalid password — cannot decrypt private key'}), 401

    # Step 5 — unwrap the FEK using RSA-OAEP with the decrypted private key
    try:
        fek = unwrap_fek(wrapped_fek, private_key)
    except Exception:
        return jsonify({'ERROR': 'Failed to unwrap file encryption key'}), 500

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
            'ERROR': 'Decryption failed — authentication tag mismatch',
            'integrity': False,
        }), 422
    except Exception as e:
        return jsonify({'ERROR': f'Decryption ERROR: {str(e)}'}), 500

    # Step 7-8 — recompute hash of decrypted plaintext and compare to stored value
    recomputed_hash = hash_file(plaintext, file_record.hash_algo)
    integrity_ok    = verify_file_integrity(plaintext, file_record.file_hash, file_record.hash_algo)

    # Step 9 — integrity result: abort with detail if mismatch, else send file
    if not integrity_ok:
        return jsonify({
            'ERROR':           'Integrity check FAILED — file has been tampered with',
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


@files_bp.route('/files/<int:file_id>/share', methods=['POST'])
@jwt_required()
def share_file(file_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)

    data = request.get_json()
    if not data or 'password' not in data or 'recipient_email' not in data:
        return jsonify({'ERROR': 'Password and Recipient Email required'}), 400

    password = data['password']
    recipient_email = data['recipient_email']

    can_edit = data.get('can_edit', False)
    expires_in_days = data.get('expires_in_days')

    file_record = db.session.get(File, file_id)
    if not file_record or file_record.owner_id != user_id:
        return jsonify({'ERROR': 'File not found or unauthorized'}), 404

    recipient = User.query.filter_by(email=recipient_email).first()
    if not recipient:
        return jsonify({'ERROR': f'No user found with email: {recipient_email}'}), 404
    if recipient.id == user_id:
        return jsonify({'ERROR': 'Cannot share a file with yourself'}), 400

    try:

        user_private_key = decrypt_private_key(
            user.private_key_enc, 
            user.private_key_salt, 
            user.private_key_nonce, 
            password
        )

        fek = unwrap_fek(
            file_record.wrapped_fek,
            user_private_key
        )

        pem = recipient.public_key_pem
        if isinstance(pem, str):
            pem = pem.encode()
        recipient_public_key = load_public_key_from_pem(pem)

        new_wrapped_fek = wrap_fek(
            fek, 
            recipient_public_key
        )

        expiration_date = None
        if expires_in_days:
            expiration_date = datetime.utcnow() + timedelta(days=int(expires_in_days))
        
        share_record = Share(
            file_id=file_record.id,
            owner_id=user_id,
            recipient_id=recipient.id,
            wrapped_fek=new_wrapped_fek,
            can_edit=can_edit,
            expires_at=expiration_date
        )
        db.session.add(share_record)
        db.session.commit()

        # Generate ID-based link and mock the email
        access_link = f"http://localhost:5000/files/{file_record.id}/download"
        print(f"\n[MOCK EMAIL SERVER] Sending email to {recipient_email}...")
        print(f"Subject: {user.email} shared a secure file with you!")
        print(f"Body: Access it here: {access_link}\n")

        return jsonify({
            'message': f'File securely shared with {recipient_email}',
            'access_link': access_link,
            'expires_at': expiration_date.isoformat() if expiration_date else None
        }), 200

    except Exception as e:
        return jsonify({'ERROR': f'Sharing failed: {str(e)}'}), 400


@files_bp.route('/files/<int:file_id>/edit', methods=['PUT'])
@jwt_required()
def edit_file(file_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)

    # Even the shared user can edit
    file_record = db.session.get(File, file_id)
    if not file_record:
        return jsonify({'ERROR': 'File not found or unauthorized'}), 404
    
    is_owner = (file_record.owner_id == user_id)
    is_authorized_editor = False

    if not is_owner:
        share = Share.query.filter_by(file_id=file_id, recipient_id=user_id).first()
        # Check expiration
        if share and share.can_edit:
            if not share.expires_at or share.expires_at > datetime.utcnow():
                is_authorized_editor = True

    if not is_owner and not is_authorized_editor:
        return jsonify({'ERROR': 'Forbidden - You do not have permission to edit this file'}), 403

  
    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'ERROR': 'No file provided'}), 400

    enc_algo  = request.form.get('enc_algo', file_record.enc_algo).lower()
    hash_algo = request.form.get('hash_algo', file_record.hash_algo).lower()

    if enc_algo not in SUPPORTED_ENC_ALGOS:
        return jsonify({'ERROR': f'Unsupported enc_algo: {enc_algo}'}), 400
    if hash_algo not in SUPPORTED_HASH_ALGOS:
        return jsonify({'ERROR': f'Unsupported hash_algo: {hash_algo}'}), 400


    plaintext = uploaded.read()

    try:

        new_hash = hash_file(
            plaintext,
            hash_algo
        )
        new_fek = generate_fek()
        new_ciphertext, new_nonce = encrypt_file(
            plaintext,
            enc_algo,
            new_fek
        )

        owner = db.session.get(User, file_record.owner_id)
        pem = owner.public_key_pem
        if isinstance(pem, str):
            pem = pem.encode()
        owner_public_key = load_public_key_from_pem(pem)
        new_wrapped_fek_owner = wrap_fek(new_fek, owner_public_key)

        existing_shares = Share.query.filter_by(file_id=file_id).all()
        for share in existing_shares:
            recipient = db.session.get(User, share.recipient_id)
            if recipient:
                r_pem = recipient.public_key_pem
                if isinstance(r_pem, str):
                    r_pem = r_pem.encode()
                recipient_pub_key = load_public_key_from_pem(r_pem)
                share.wrapped_fek = wrap_fek(new_fek, recipient_pub_key)

        # Update File
        file_record.filename = uploaded.filename
        file_record.file_size = len(plaintext)
        file_record.ciphertext = new_ciphertext
        file_record.wrapped_fek = new_wrapped_fek_owner
        file_record.nonce = new_nonce
        file_record.file_hash = new_hash
        file_record.enc_algo    = enc_algo
        file_record.hash_algo   = hash_algo
        file_record.upload_date = datetime.utcnow()

        db.session.commit()

        return jsonify({
        'message': 'File updated and re-encrypted successfully',
        'file_id': file_id,
        'new_hash': new_hash,
        'enc_algo': enc_algo,
        'recipients_rekeyed': len(existing_shares)
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'ERROR': f'Edit failed due to server error: {str(e)}'}), 500





        