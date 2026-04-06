from flask import Blueprint, request, jsonify
from models import db, User
from crypto import (
    hash_password, verify_password,
    generate_rsa_keypair, serialize_public_key,
    encrypt_private_key, decrypt_private_key
)

auth_bp = Blueprint('auth', __name__)

#register route
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email    = data.get('email')
    password = data.get('password')

    # Checking if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    # Hashing the password with bcrypt
    password_hash = hash_password(password)

    # RSA key pair for this user
    private_key, public_key = generate_rsa_keypair()

    # Serialize public key
    public_key_pem = serialize_public_key(public_key)

    # encrypt private key using password-derived AES key
    private_key_enc, salt, nonce = encrypt_private_key(private_key, password)

    # save everything to DB
    user = User(
        email=email,
        password_hash=password_hash,
        public_key_pem=public_key_pem,
        private_key_enc=private_key_enc,
        private_key_salt=salt,
        private_key_nonce=nonce
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201