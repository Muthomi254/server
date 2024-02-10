from flask import Blueprint, jsonify, request
from models import db, User
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'message': 'Request body must be in JSON format'}), 400

        username = data.get('username')
        email = data.get('email')
        phone_number = data.get('phone_number')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            return jsonify({'message': 'Missing username, email, password, or confirm_password'}), 400

        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'message': 'Username or email already exists'}), 400

        new_user = User(username=username, email=email, phone_number=phone_number)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        return jsonify({'message': str(e)}), 500



@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username:
        return jsonify({'message': 'Missing username'}), 400

    if not password:
        return jsonify({'message': 'Missing password'}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200

    return jsonify({'message': 'Invalid username or password'}), 401
    
@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if user:
        profile_data = {
            'username': user.username,
            'email': user.email,  # Include email in the profile data
            'phone_number': user.phone_number,  # Include phone_number in the profile data
            'description': user.description,
            'last_seen': user.last_seen.isoformat() if user.last_seen else None
        }
        return jsonify(profile_data), 200

    return jsonify({'message': 'User not found'}), 404


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'message': 'Request body must be in JSON format'}), 400

        username = data.get('username')
        email = data.get('email')
        new_password = data.get('new_password')

        if not username or not email or not new_password:
            return jsonify({'message': 'Missing username, email, or new password'}), 400

        user = User.query.filter_by(username=username, email=email).first()

        if not user:
            return jsonify({'message': 'Invalid username or email'}), 404

        # Generate a new password hash
        new_password_hash = generate_password_hash(new_password)

        # Update the user's password hash
        user.password_hash = new_password_hash
        db.session.commit()

        return jsonify({'message': 'Password reset successful'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

        
            

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Add any additional logout logic if needed
    return jsonify({'message': 'Logged out successfully'}), 200
