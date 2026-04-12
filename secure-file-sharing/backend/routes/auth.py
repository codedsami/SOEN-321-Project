from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required
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

#login route
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email    = data.get('email')
    password = data.get('password')

    # Look up the user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    # Verify bcrypt password hash
    if not verify_password(password, user.password_hash):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Decrypt the RSA private key using the password
    private_key = decrypt_private_key(
        user.private_key_enc,
        user.private_key_salt,
        user.private_key_nonce,
        password
    )

    # Return success
    access_token = create_access_token(identity=str(user.id))
    return jsonify({'access_token': access_token, 'user_id': user.id}), 200

#logout route
@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'message': 'Logged out successfully. Please delete your token.'}), 200


   
