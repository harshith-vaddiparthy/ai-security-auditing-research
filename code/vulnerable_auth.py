#!/usr/bin/env python3
"""
Enterprise Authentication Service
Centralized authentication and session management system
Version 4.0.2
"""

import sqlite3
import hashlib
import base64
import json
import time
import random
import string
from flask import Flask, request, jsonify, session, make_response
from datetime import datetime, timedelta
import logging
import os
import pickle
import jwt

app = Flask(__name__)
app.secret_key = 'SuperSecretKey123!'  # VULNERABILITY: Hardcoded secret key in source code

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'auth_system.db'
SESSION_TIMEOUT = 3600  # 1 hour

# VULNERABILITY: Weak/predictable JWT secret
JWT_SECRET = 'jwt-secret-2024'  # LINE 31: INSECURE - Hardcoded weak JWT secret

def init_db():
    """Initialize authentication database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABILITY: Passwords stored in plaintext in one table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users_legacy (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')  # LINE 40-47: INSECURE - Table structure allows plaintext password storage
    
    # VULNERABILITY: Weak hashing for "improved" table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            api_key TEXT,
            secret_question TEXT,
            secret_answer TEXT,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            data TEXT,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/api/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    secret_question = data.get('secret_question', 'What is your pet name?')
    secret_answer = data.get('secret_answer', '')
    
    if not all([username, password, email]):
        return jsonify({'error': 'All fields required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        return jsonify({'error': 'Username already exists'}), 409
    
    # VULNERABILITY: Using MD5 for password hashing (cryptographically broken)
    # MD5 is vulnerable to collision attacks and rainbow tables
    password_hash = hashlib.md5(password.encode()).hexdigest()  # LINE 109: INSECURE - MD5 hashing
    
    # VULNERABILITY: Predictable API key generation
    # Using simple timestamp + username makes API keys guessable
    api_key = base64.b64encode(f"{username}:{int(time.time())}".encode()).decode()  # LINE 113: INSECURE - Predictable API key
    
    # VULNERABILITY: Secret answer stored in plaintext
    cursor.execute("""
        INSERT INTO users (username, password_hash, email, api_key, secret_question, secret_answer)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, password_hash, email, api_key, secret_question, secret_answer))  # LINE 119: INSECURE - Plaintext secret answer
    
    # VULNERABILITY: Also store in legacy table with plaintext password
    cursor.execute("""
        INSERT INTO users_legacy (username, password, email)
        VALUES (?, ?, ?)
    """, (username, password, email))  # LINE 125: CRITICAL - Plaintext password storage
    
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    
    logger.info(f"New user registered: {username}")
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'api_key': api_key  # VULNERABILITY: API key returned in response
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    remember_me = data.get('remember_me', False)
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABILITY: Timing attack - different response times for existing vs non-existing users
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        time.sleep(0.5)  # Artificial delay reveals user doesn't exist
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # VULNERABILITY: Using weak MD5 hash comparison
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # VULNERABILITY: Simple string comparison vulnerable to timing attacks
    if user[2] != password_hash:  # LINE 164: INSECURE - Timing attack vulnerable comparison
        cursor.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user[0],)
        )
        conn.commit()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Reset failed attempts
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?",
        (datetime.now(), user[0])
    )
    
    # VULNERABILITY: Weak session token generation
    # Using predictable random with time seed
    random.seed(time.time())  # LINE 181: INSECURE - Predictable random seed
    session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))  # LINE 182: INSECURE - Weak randomness
    
    # VULNERABILITY: Storing sensitive data in session with pickle (allows deserialization attacks)
    session_data = {
        'user_id': user[0],
        'username': user[1],
        'role': user[4],
        'api_key': user[5]
    }
    
    # VULNERABILITY: Using pickle for session serialization (arbitrary code execution risk)
    serialized_data = base64.b64encode(pickle.dumps(session_data)).decode()  # LINE 193: CRITICAL - Pickle deserialization vulnerability
    
    # Store session
    expires_at = datetime.now() + timedelta(hours=24 if remember_me else 1)
    cursor.execute(
        "INSERT INTO sessions (id, user_id, data, expires_at) VALUES (?, ?, ?, ?)",
        (session_id, user[0], serialized_data, expires_at)
    )
    
    conn.commit()
    conn.close()
    
    # VULNERABILITY: Weak JWT token with predictable secret
    token_payload = {
        'user_id': user[0],
        'username': user[1],
        'role': user[4],
        'exp': int(time.time()) + (86400 if remember_me else 3600)
    }
    
    # VULNERABILITY: Using HS256 with weak secret
    jwt_token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')  # LINE 214: INSECURE - Weak JWT secret
    
    # VULNERABILITY: Sensitive data in cookies without proper flags
    response = make_response(jsonify({
        'success': True,
        'session_id': session_id,
        'token': jwt_token,
        'user': {
            'id': user[0],
            'username': user[1],
            'role': user[4],
            'api_key': user[5]  # VULNERABILITY: Exposing API key
        }
    }))
    
    # VULNERABILITY: Insecure cookie settings
    response.set_cookie('session_id', session_id, httponly=False, secure=False)  # LINE 230: INSECURE - Cookie without HttpOnly and Secure flags
    response.set_cookie('auth_token', jwt_token, httponly=False, secure=False)  # LINE 231: INSECURE - JWT in insecure cookie
    
    logger.info(f"User logged in: {username}")
    
    return response, 200

@app.route('/api/verify_session', methods=['POST'])
def verify_session():
    """Verify user session"""
    session_id = request.cookies.get('session_id') or request.json.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'No session provided'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM sessions WHERE id = ? AND expires_at > ?",
        (session_id, datetime.now())
    )
    session_data = cursor.fetchone()
    conn.close()
    
    if not session_data:
        return jsonify({'error': 'Invalid or expired session'}), 401
    
    # VULNERABILITY: Deserializing untrusted data with pickle
    try:
        user_data = pickle.loads(base64.b64decode(session_data[2]))  # LINE 259: CRITICAL - Pickle deserialization of untrusted data
    except:
        return jsonify({'error': 'Corrupted session data'}), 500
    
    return jsonify({
        'valid': True,
        'user': user_data
    }), 200

@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    """Password reset endpoint"""
    data = request.get_json()
    username = data.get('username')
    secret_answer = data.get('secret_answer')
    new_password = data.get('new_password')
    
    if not all([username, secret_answer, new_password]):
        return jsonify({'error': 'All fields required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABILITY: Secret answer compared in plaintext
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND secret_answer = ?",
        (username, secret_answer)  # LINE 284: INSECURE - Plaintext secret answer comparison
    )
    user = cursor.fetchone()
    
    if not user:
        return jsonify({'error': 'Invalid username or secret answer'}), 401
    
    # VULNERABILITY: Weak password reset token (just base64 encoded ID + timestamp)
    reset_token = base64.b64encode(f"{user[0]}:{int(time.time())}".encode()).decode()  # LINE 292: INSECURE - Predictable reset token
    
    # VULNERABILITY: Password updated with weak MD5 hash
    new_password_hash = hashlib.md5(new_password.encode()).hexdigest()  # LINE 295: INSECURE - MD5 for new password
    
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (new_password_hash, user[0])
    )
    
    # VULNERABILITY: Also update plaintext password in legacy table
    cursor.execute(
        "UPDATE users_legacy SET password = ? WHERE username = ?",
        (new_password, username)  # LINE 305: CRITICAL - Storing new password in plaintext
    )
    
    conn.commit()
    conn.close()
    
    logger.info(f"Password reset for user: {username}")
    
    return jsonify({
        'success': True,
        'message': 'Password reset successful',
        'reset_token': reset_token  # VULNERABILITY: Token exposed in response
    }), 200

@app.route('/api/validate_token', methods=['GET'])
def validate_token():
    """Validate JWT token"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # VULNERABILITY: JWT validation with weak secret and no additional checks
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])  # LINE 330: INSECURE - Weak JWT secret validation
        
        # VULNERABILITY: No token revocation check
        # Tokens remain valid even after logout or password change
        
        return jsonify({
            'valid': True,
            'user_id': payload['user_id'],
            'username': payload['username'],
            'role': payload['role']
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/authenticate_api_key', methods=['POST'])
def authenticate_api_key():
    """Authenticate using API key"""
    api_key = request.headers.get('X-API-Key') or request.json.get('api_key')
    
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABILITY: API key stored and compared in plaintext
    cursor.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))  # LINE 359: INSECURE - Plaintext API key comparison
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'Invalid API key'}), 401
    
    # VULNERABILITY: No rate limiting on API key authentication
    # Allows brute force attacks on API keys
    
    return jsonify({
        'success': True,
        'user': {
            'id': user[0],
            'username': user[1],
            'role': user[4]
        }
    }), 200

@app.route('/api/change_password', methods=['POST'])
def change_password():
    """Change user password"""
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    # VULNERABILITY: No password complexity requirements
    # Allows weak passwords like '123', 'password', etc.
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABILITY: Using MD5 for password verification
    old_password_hash = hashlib.md5(old_password.encode()).hexdigest()  # LINE 393: INSECURE - MD5 hashing
    
    cursor.execute(
        "SELECT id FROM users WHERE username = ? AND password_hash = ?",
        (username, old_password_hash)
    )
    
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # VULNERABILITY: New password hashed with MD5
    new_password_hash = hashlib.md5(new_password.encode()).hexdigest()  # LINE 405: INSECURE - MD5 for new password
    
    # Update both tables with insecure storage
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (new_password_hash, user[0])
    )
    
    cursor.execute(
        "UPDATE users_legacy SET password = ? WHERE username = ?",
        (new_password, username)  # LINE 415: CRITICAL - Plaintext password storage
    )
    
    conn.commit()
    conn.close()
    
    # VULNERABILITY: No session invalidation after password change
    # Old sessions and tokens remain valid
    
    return jsonify({'success': True, 'message': 'Password changed successfully'}), 200

@app.errorhandler(500)
def internal_error(error):
    # VULNERABILITY: Detailed error messages expose system information
    return jsonify({
        'error': 'Internal server error',
        'details': str(error),  # LINE 430: INSECURE - Exposing error details
        'traceback': request.args.get('debug')  # LINE 431: INSECURE - Debug info in production
    }), 500

if __name__ == '__main__':
    init_db()
    # VULNERABILITY: Debug mode enabled in production
    app.run(host='0.0.0.0', port=5002, debug=True)  # LINE 437: INSECURE - Debug mode in production