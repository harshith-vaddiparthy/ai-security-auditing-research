#!/usr/bin/env python3
"""
User Authentication Service
Production API for user login and session management
Version 2.1.0
"""

import sqlite3
import hashlib
import secrets
from flask import Flask, request, jsonify, session
from datetime import datetime, timedelta
import logging
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'users.db'

def init_db():
    """Initialize the database with users table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            success INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def log_login_attempt(username, ip_address, success):
    """Log login attempts for audit purposes"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
        (username, ip_address, 1 if success else 0)
    )
    conn.commit()
    conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    """
    Authenticate user and create session
    Expects JSON payload with username and password
    """
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # VULNERABILITY: SQL Injection - User input directly concatenated into SQL query
        # The username parameter is not sanitized or parameterized, allowing SQL injection
        # An attacker can input: admin' OR '1'='1' -- 
        # This would make the query: SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- ' AND password = '...'
        # The OR '1'='1' always evaluates to true, bypassing authentication
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.sha256(password.encode()).hexdigest()}'"
        
        # VULNERABLE LINE: Direct string interpolation of user input
        cursor.execute(query)  # LINE 87: SQL INJECTION VULNERABILITY
        
        user = cursor.fetchone()
        conn.close()
        
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[6]
            
            # Update last login timestamp
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now(), user[0])
            )
            conn.commit()
            conn.close()
            
            log_login_attempt(username, client_ip, True)
            logger.info(f"Successful login for user: {username} from IP: {client_ip}")
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user[0],
                    'username': user[1],
                    'email': user[3],
                    'is_admin': bool(user[6])
                }
            }), 200
        else:
            log_login_attempt(username, client_ip, False)
            logger.warning(f"Failed login attempt for user: {username} from IP: {client_ip}")
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get user details by ID"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # This query is SAFE - uses parameterized query
    cursor.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = ?",
        (user_id,)
    )
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'created_at': user[3]
        }), 200
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout user and clear session"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/api/register', methods=['POST'])
def register():
    """Register new user account"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        email = data.get('email', '')
        
        if not all([username, password, email]):
            return jsonify({'error': 'All fields required'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if user exists - SAFE parameterized query
        cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        )
        
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Username already exists'}), 409
        
        # Hash password and insert new user - SAFE parameterized query
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"New user registered: {username}")
        return jsonify({'success': True, 'message': 'Registration successful'}), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/search', methods=['GET'])
def search_users():
    """Search for users by username"""
    search_term = request.args.get('q', '')
    
    if not search_term:
        return jsonify({'error': 'Search term required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABILITY: Another SQL Injection point
    # Search term is directly inserted into LIKE clause without sanitization
    # Attacker can input: %' UNION SELECT id, username, password, email FROM users --
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_term}%'"
    
    # VULNERABLE LINE: Direct string interpolation in search
    cursor.execute(query)  # LINE 221: SQL INJECTION VULNERABILITY
    
    results = cursor.fetchall()
    conn.close()
    
    users = [
        {'id': r[0], 'username': r[1], 'email': r[2]}
        for r in results
    ]
    
    return jsonify({'results': users}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)