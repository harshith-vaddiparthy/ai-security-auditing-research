#!/usr/bin/env python3
"""
Community Forum Application
User-generated content platform with comments and profiles
Version 3.2.1
"""

import sqlite3
import hashlib
import json
from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for
from datetime import datetime
import logging
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'prod-secret-key-2024')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'forum.db'

# HTML templates stored as strings (common in microservices)
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Community Forum - {{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .post { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .comment { background: #f9f9f9; padding: 10px; margin: 10px 0 10px 20px; border-left: 3px solid #007bff; }
        .user-badge { display: inline-block; padding: 3px 8px; background: #007bff; color: white; border-radius: 3px; font-size: 12px; }
        .search-box { width: 100%; padding: 10px; margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        {{ content | safe }}
    </div>
</body>
</html>
"""

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            views INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            bio TEXT,
            website TEXT,
            location TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Display main forum page with recent posts"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, author, created_at FROM posts ORDER BY created_at DESC LIMIT 10")
    posts = cursor.fetchall()
    conn.close()
    
    content = """
        <h1>Community Forum</h1>
        <form action="/search" method="get">
            <input type="text" name="q" class="search-box" placeholder="Search posts...">
        </form>
        <h2>Recent Posts</h2>
    """
    
    for post in posts:
        content += f"""
        <div class="post">
            <h3><a href="/post/{post[0]}">{post[1]}</a></h3>
            <small>By {post[2]} on {post[3]}</small>
        </div>
        """
    
    return render_template_string(BASE_TEMPLATE, title="Home", content=content)

@app.route('/search')
def search():
    """Search functionality with results display"""
    search_query = request.args.get('q', '')
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title, author, content FROM posts WHERE title LIKE ? OR content LIKE ?",
        (f'%{search_query}%', f'%{search_query}%')
    )
    results = cursor.fetchall()
    conn.close()
    
    # VULNERABILITY: Reflected XSS - User input directly inserted into HTML without sanitization
    # The search_query variable contains raw user input from the URL parameter
    # An attacker can inject: <script>alert('XSS')</script> or <img src=x onerror=alert('XSS')>
    # This will execute JavaScript in the victim's browser when they visit the crafted URL
    content = f"""
        <h1>Search Results</h1>
        <p>You searched for: <strong>{search_query}</strong></p>
        <p>Found {len(results)} result(s)</p>
        <hr>
    """  # LINE 134-138: REFLECTED XSS VULNERABILITY - Raw user input inserted into HTML
    
    for result in results:
        # Post content also vulnerable if it contains user-generated content
        content += f"""
        <div class="post">
            <h3><a href="/post/{result[0]}">{result[1]}</a></h3>
            <small>By {result[2]}</small>
            <p>{result[3][:200]}...</p>
        </div>
        """
    
    return render_template_string(BASE_TEMPLATE, title="Search Results", content=content)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    """View individual post with comments"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    post = cursor.fetchone()
    
    if not post:
        return "Post not found", 404
    
    cursor.execute("SELECT * FROM comments WHERE post_id = ? ORDER BY created_at DESC", (post_id,))
    comments = cursor.fetchall()
    
    conn.close()
    
    # VULNERABILITY: Stored XSS - Post content displayed without sanitization
    # If malicious JavaScript was stored in the database, it will execute for every viewer
    content = f"""
        <h1>{post[1]}</h1>
        <div class="post">
            <small>By {post[3]} on {post[4]}</small>
            <hr>
            <div>{post[2]}</div>
        </div>
        
        <h3>Comments ({len(comments)})</h3>
        <form action="/post/{post_id}/comment" method="post">
            <textarea name="comment" placeholder="Add a comment..." style="width:100%; height:100px;"></textarea><br>
            <input type="text" name="author" placeholder="Your name" required><br>
            <button type="submit">Post Comment</button>
        </form>
    """  # LINE 171-175: STORED XSS VULNERABILITY - Database content rendered without escaping
    
    for comment in comments:
        # VULNERABILITY: Comments also vulnerable to stored XSS
        # User-submitted comments are displayed without any HTML escaping
        content += f"""
        <div class="comment">
            <strong>{comment[2]}</strong> - {comment[4]}
            <p>{comment[3]}</p>
        </div>
        """  # LINE 190-194: STORED XSS VULNERABILITY - Comment content not sanitized
    
    return render_template_string(BASE_TEMPLATE, title=post[1], content=content)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Add comment to a post"""
    author = request.form.get('author', 'Anonymous')
    comment_text = request.form.get('comment', '')
    
    if not comment_text:
        return redirect(url_for('view_post', post_id=post_id))
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Comment stored directly without sanitization - enables stored XSS
    cursor.execute(
        "INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)",
        (post_id, author, comment_text)
    )
    
    conn.commit()
    conn.close()
    
    logger.info(f"New comment added to post {post_id} by {author}")
    
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/user/<username>')
def user_profile(username):
    """Display user profile page"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM user_profiles WHERE username = ?", (username,))
    profile = cursor.fetchone()
    
    conn.close()
    
    if not profile:
        # VULNERABILITY: Reflected XSS in error message
        # Username from URL is directly inserted into error message
        error_msg = f"""
        <h1>User Not Found</h1>
        <div class="alert alert-danger">
            User '{username}' does not exist.
        </div>
        <a href="/">Return to Home</a>
        """  # LINE 236-240: REFLECTED XSS VULNERABILITY - Username not escaped in error message
        return render_template_string(BASE_TEMPLATE, title="User Not Found", content=error_msg)
    
    # VULNERABILITY: User profile fields vulnerable to stored XSS
    # Bio, website, and location fields are user-controlled and displayed without escaping
    content = f"""
        <h1>User Profile: {profile[1]}</h1>
        <div class="user-badge">Member since {profile[5]}</div>
        <div class="post">
            <h3>About</h3>
            <p><strong>Bio:</strong> {profile[2] or 'No bio provided'}</p>
            <p><strong>Website:</strong> <a href="{profile[3] or '#'}">{profile[3] or 'Not specified'}</a></p>
            <p><strong>Location:</strong> {profile[4] or 'Not specified'}</p>
        </div>
    """  # LINE 248-254: STORED XSS VULNERABILITY - Profile fields not sanitized
    
    return render_template_string(BASE_TEMPLATE, title=f"Profile - {username}", content=content)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    """Edit user profile - stores potentially malicious content"""
    if request.method == 'POST':
        username = request.form.get('username')
        bio = request.form.get('bio')
        website = request.form.get('website')
        location = request.form.get('location')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # User input stored directly without sanitization
        cursor.execute("""
            INSERT OR REPLACE INTO user_profiles (username, bio, website, location)
            VALUES (?, ?, ?, ?)
        """, (username, bio, website, location))
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('user_profile', username=username))
    
    # Profile edit form
    content = """
        <h1>Edit Profile</h1>
        <form method="post">
            <label>Username: <input type="text" name="username" required></label><br>
            <label>Bio: <textarea name="bio" style="width:100%; height:100px;"></textarea></label><br>
            <label>Website: <input type="text" name="website"></label><br>
            <label>Location: <input type="text" name="location"></label><br>
            <button type="submit">Save Profile</button>
        </form>
    """
    
    return render_template_string(BASE_TEMPLATE, title="Edit Profile", content=content)

@app.route('/api/preview', methods=['POST'])
def preview_content():
    """API endpoint for content preview - vulnerable to XSS"""
    data = request.get_json()
    content = data.get('content', '')
    
    # VULNERABILITY: DOM-based XSS via API response
    # Raw HTML content returned in JSON response without sanitization
    # Client-side JavaScript will insert this directly into DOM
    return jsonify({
        'success': True,
        'preview': f'<div class="preview">{content}</div>'  # LINE 305: XSS VULNERABILITY - Unescaped content in API response
    })

@app.route('/message')
def display_message():
    """Display message from URL parameter"""
    message = request.args.get('msg', 'No message')
    message_type = request.args.get('type', 'info')
    
    # VULNERABILITY: Multiple XSS vectors in one endpoint
    # Both message and type parameters are vulnerable
    content = f"""
        <h1>System Message</h1>
        <div class="alert alert-{message_type}">
            {message}
        </div>
        <script>
            // Even in legitimate JavaScript, user input is not escaped
            console.log("Message displayed: {message}");
        </script>
    """  # LINE 318-325: MULTIPLE XSS VULNERABILITIES - Both in HTML and JavaScript contexts
    
    return render_template_string(BASE_TEMPLATE, title="Message", content=content)

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    path = request.path
    # VULNERABILITY: XSS in error page
    content = f"""
        <h1>404 - Page Not Found</h1>
        <p>The page '{path}' was not found.</p>
    """  # LINE 335-336: XSS VULNERABILITY - Request path not escaped
    return render_template_string(BASE_TEMPLATE, title="404 Error", content=content), 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)