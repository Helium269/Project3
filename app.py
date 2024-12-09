from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import uuid
from datetime import datetime
from argon2 import PasswordHasher
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize the Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

# Initialize the database and password hasher
db = SQLAlchemy(app)
ph = PasswordHasher()

# Initialize the Limiter correctly
limiter = Limiter(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(100), nullable=False)
    request_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('auth_logs', lazy=True))

# Helper Functions
def encrypt_private_key(key):
    """
    Encrypt the private key using AES encryption with a key from environment variable.
    """
    encryption_key = os.getenv('NOT_MY_KEY', 'default_encryption_key')  # Fallback key if not set
    iv = os.urandom(16)  # Random IV for each encryption
    cipher = Cipher(algorithms.AES(encryption_key.encode()), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(key.encode()) + encryptor.finalize()
    return iv + encrypted_key  # Store the IV along with the encrypted key

# Routes
@app.route('/register', methods=['POST'])
def register_user():
    """
    Register a new user, generate a UUIDv4 password, hash it using Argon2,
    and store it in the database.
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    # Generate UUIDv4 password
    password = str(uuid.uuid4())
    hashed_password = ph.hash(password)

    # Create the user and add to the database
    new_user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"password": password}), 201

@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")  # Rate limit: 10 requests per second
def authenticate_user():
    """
    Authenticate a user by username and password, log the request, and return success.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and ph.verify(user.password_hash, password):
        # Log the authentication request
        auth_log = AuthLog(request_ip=request.remote_addr, user_id=user.id)
        db.session.add(auth_log)
        db.session.commit()
        return jsonify({"message": "Authentication successful!"}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401

# Initialize the database
@app.before_request
def create_tables():
    """
    Create the database tables before the first request.
    """
    db.create_all()

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)

