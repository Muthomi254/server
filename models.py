from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.event import listens_for
from sqlalchemy.orm import validates
from email_validator import validate_email, EmailNotValidError

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(14), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Event listener for username
@listens_for(User, 'before_insert')
@listens_for(User, 'before_update')
def uppercase_username(mapper, connection, target):
    target.username = target.username.upper()

# Validator for phone_number
@validates('phone_number')
def validate_phone_number(key, phone_number):
    if phone_number is not None and len(phone_number) <= 14:
        return phone_number
    raise ValueError("Phone number must be a string with a maximum length of 14 characters.")

# Validator for email
@validates('email')
def validate_email(key, email):
    try:
        v = validate_email(email)
        return v.email
    except EmailNotValidError as e:
        raise ValueError(f"Invalid email: {e}")
