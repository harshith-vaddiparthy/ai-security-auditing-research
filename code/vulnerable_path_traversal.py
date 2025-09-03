#!/usr/bin/env python3
"""
Enterprise Document Management System
Cloud-based file storage and sharing platform
Version 5.1.3
"""

import os
import shutil
import mimetypes
import hashlib
import json
import zipfile
import tarfile
from flask import Flask, request, send_file, jsonify, render_template_string, abort
from werkzeug.utils import secure_filename
from datetime import datetime
import logging
import sqlite3
import tempfile
import subprocess

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.secret_key = os.environ.get('SECRET_KEY', 'document-manager-secret-2024')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base directories for file storage
UPLOAD_FOLDER = '/var/www/documents/uploads'
TEMP_FOLDER = '/var/www/documents/temp'
BACKUP_FOLDER = '/var/www/documents/backups'
USER_FOLDERS = '/var/www/documents/users'
TEMPLATE_FOLDER = '/var/www/documents/templates'

# Create directories if they don't exist
for folder in [UPLOAD_FOLDER, TEMP_FOLDER, BACKUP_FOLDER, USER_FOLDERS, TEMPLATE_FOLDER]:
    os.makedirs(folder, exist_ok=True)

DATABASE = 'documents.db'

def init_db():
    """Initialize document database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            mime_type TEXT,
            upload_user TEXT,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            downloads INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """File upload endpoint"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    username = request.form.get('username', 'anonymous')
    folder = request.form.get('folder', '')  # User-specified subfolder
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # VULNERABILITY: User-controlled folder path without proper validation
    # Attacker can use ../../../ to escape the intended directory
    # Example: folder = "../../../../etc/" could write to system directories
    if folder:
        # No validation of folder parameter - allows directory traversal
        upload_path = os.path.join(UPLOAD_FOLDER, folder)  # LINE 81: PATH TRAVERSAL - User input directly in path
    else:
        upload_path = UPLOAD_FOLDER
    
    # Create user-specified directory if it doesn't exist
    os.makedirs(upload_path, exist_ok=True)
    
    # Generate unique filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{file.filename}"
    
    # VULNERABILITY: Filename not properly sanitized
    # Even though we add timestamp, the original filename could contain path traversal sequences
    file_path = os.path.join(upload_path, filename)  # LINE 94: PATH TRAVERSAL - Filename could contain ../
    
    # Save file to disk
    file.save(file_path)
    
    # Get file info
    file_size = os.path.getsize(file_path)
    mime_type = mimetypes.guess_type(file_path)[0]
    
    # Store in database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO documents (filename, original_name, file_path, file_size, mime_type, upload_user)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (filename, file.filename, file_path, file_size, mime_type, username))
    
    doc_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    logger.info(f"File uploaded: {filename} by {username}")
    
    return jsonify({
        'success': True,
        'document_id': doc_id,
        'filename': filename,
        'size': file_size
    }), 201

@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    """File download endpoint with path parameter"""
    # VULNERABILITY: Path parameter allows directory traversal
    # User can request: /api/download/../../../../etc/passwd
    # The 'path:' converter captures everything including slashes
    
    # VULNERABILITY: Direct path concatenation without validation
    file_path = os.path.join(UPLOAD_FOLDER, filename)  # LINE 131: CRITICAL PATH TRAVERSAL - Direct use of user input
    
    # VULNERABILITY: Only checking if file exists, not if it's within allowed directory
    if not os.path.exists(file_path):  # LINE 134: INSUFFICIENT VALIDATION - Only checks existence
        return jsonify({'error': 'File not found'}), 404
    
    # Log download
    logger.info(f"File downloaded: {filename}")
    
    # VULNERABILITY: Sending file without checking if it's outside UPLOAD_FOLDER
    return send_file(file_path, as_attachment=True)  # LINE 141: SERVES ANY ACCESSIBLE FILE

@app.route('/api/download_by_id/<int:doc_id>', methods=['GET'])
def download_by_id(doc_id):
    """Download file by database ID"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT file_path, original_name FROM documents WHERE id = ?", (doc_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Document not found'}), 404
    
    file_path, original_name = result
    
    # VULNERABILITY: file_path from database is trusted but could have been manipulated
    # If an attacker modified the database, they could set file_path to any system file
    if not os.path.exists(file_path):  # LINE 159: TRUSTING DATABASE CONTENT
        return jsonify({'error': 'File not found on disk'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=original_name)

@app.route('/api/read_template', methods=['POST'])
def read_template():
    """Read template file for document generation"""
    data = request.get_json()
    template_name = data.get('template', 'default.txt')
    
    # VULNERABILITY: Template name used directly in path construction
    # Attacker can use: "../../../etc/passwd" as template name
    template_path = os.path.join(TEMPLATE_FOLDER, template_name)  # LINE 172: PATH TRAVERSAL - Template name in path
    
    try:
        # VULNERABILITY: Reading file without validating it's within TEMPLATE_FOLDER
        with open(template_path, 'r') as f:  # LINE 176: READING ARBITRARY FILES
            content = f.read()
        
        return jsonify({
            'success': True,
            'template_content': content
        }), 200
    except FileNotFoundError:
        return jsonify({'error': 'Template not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup', methods=['POST'])
def create_backup():
    """Create backup of user documents"""
    data = request.get_json()
    username = data.get('username', 'anonymous')
    backup_name = data.get('backup_name', f'backup_{datetime.now().strftime("%Y%m%d")}.zip')
    
    # VULNERABILITY: Backup name can contain path traversal sequences
    # Attacker can specify: "../../../../tmp/malicious.zip"
    backup_path = os.path.join(BACKUP_FOLDER, username, backup_name)  # LINE 197: PATH TRAVERSAL - Backup name in path
    
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    
    # Create zip backup
    with zipfile.ZipFile(backup_path, 'w') as zipf:
        user_folder = os.path.join(USER_FOLDERS, username)
        if os.path.exists(user_folder):
            for root, dirs, files in os.walk(user_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, user_folder)
                    zipf.write(file_path, arcname)
    
    return jsonify({
        'success': True,
        'backup_path': backup_path
    }), 200

@app.route('/api/restore', methods=['POST'])
def restore_backup():
    """Restore documents from backup"""
    data = request.get_json()
    username = data.get('username', 'anonymous')
    backup_file = data.get('backup_file')
    
    if not backup_file:
        return jsonify({'error': 'Backup file required'}), 400
    
    # VULNERABILITY: Backup file path traversal
    # User can specify: "../../other_user/backup.zip" to access other users' backups
    backup_path = os.path.join(BACKUP_FOLDER, username, backup_file)  # LINE 228: PATH TRAVERSAL - Backup file in path
    
    if not os.path.exists(backup_path):
        return jsonify({'error': 'Backup not found'}), 404
    
    # VULNERABILITY: Extracting zip without validating target paths
    # Zip slip vulnerability - malicious zip can extract files outside intended directory
    restore_path = os.path.join(USER_FOLDERS, username)
    os.makedirs(restore_path, exist_ok=True)
    
    with zipfile.ZipFile(backup_path, 'r') as zipf:
        # VULNERABILITY: extractall without path validation
        zipf.extractall(restore_path)  # LINE 240: ZIP SLIP VULNERABILITY - No path validation
    
    return jsonify({'success': True, 'message': 'Backup restored'}), 200

@app.route('/api/delete/<path:filepath>', methods=['DELETE'])
def delete_file(filepath):
    """Delete a file from the system"""
    # VULNERABILITY: Deleting files based on user-provided path
    # Attacker can delete any file accessible to the application
    # Example: /api/delete/../../../../etc/important.conf
    
    # VULNERABILITY: Only checking if path starts with upload folder (can be bypassed)
    full_path = os.path.join(UPLOAD_FOLDER, filepath)  # LINE 252: PATH TRAVERSAL - User controlled path
    
    # Weak validation - can be bypassed with symbolic links
    if not full_path.startswith(UPLOAD_FOLDER):  # LINE 255: INSUFFICIENT VALIDATION
        return jsonify({'error': 'Invalid path'}), 403
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        os.remove(full_path)  # LINE 262: DELETING USER-SPECIFIED FILE
        logger.info(f"File deleted: {filepath}")
        return jsonify({'success': True, 'message': 'File deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/include_file', methods=['POST'])
def include_file():
    """Include file content in response (for previews)"""
    data = request.get_json()
    file_path = data.get('file_path')
    file_type = data.get('type', 'text')
    
    if not file_path:
        return jsonify({'error': 'File path required'}), 400
    
    # VULNERABILITY: Local file inclusion
    # User can specify any file path to read sensitive files
    # Example: "/etc/passwd", "/proc/self/environ", application source code
    
    # VULNERABILITY: No validation of file_path parameter
    full_path = os.path.join(UPLOAD_FOLDER, file_path)  # LINE 283: PATH TRAVERSAL - LFI vulnerability
    
    try:
        if file_type == 'text':
            with open(full_path, 'r') as f:  # LINE 287: LOCAL FILE INCLUSION
                content = f.read()
        else:
            with open(full_path, 'rb') as f:
                content = f.read().hex()
        
        return jsonify({
            'success': True,
            'content': content,
            'path': full_path  # VULNERABILITY: Exposing full path
        }), 200
    except Exception as e:
        # VULNERABILITY: Detailed error messages reveal path information
        return jsonify({'error': f'Failed to read file: {str(e)}'}), 500  # LINE 300: INFORMATION DISCLOSURE

@app.route('/api/export', methods=['POST'])
def export_documents():
    """Export documents to various formats"""
    data = request.get_json()
    export_format = data.get('format', 'pdf')
    source_file = data.get('source')
    output_name = data.get('output', 'export')
    
    if not source_file:
        return jsonify({'error': 'Source file required'}), 400
    
    # VULNERABILITY: Command injection through file paths
    # User controls source_file and output_name used in shell commands
    source_path = os.path.join(UPLOAD_FOLDER, source_file)  # LINE 315: PATH TRAVERSAL
    output_path = os.path.join(TEMP_FOLDER, f"{output_name}.{export_format}")  # LINE 316: PATH TRAVERSAL
    
    # VULNERABILITY: Using user input in shell command
    if export_format == 'pdf':
        # Command injection possible through source_path or output_path
        cmd = f"convert {source_path} {output_path}"  # LINE 321: COMMAND INJECTION
        subprocess.run(cmd, shell=True)  # LINE 322: SHELL INJECTION VULNERABILITY
    
    if os.path.exists(output_path):
        return send_file(output_path, as_attachment=True)
    else:
        return jsonify({'error': 'Export failed'}), 500

@app.route('/api/list_directory', methods=['GET'])
def list_directory():
    """List files in a directory"""
    directory = request.args.get('dir', '.')
    
    # VULNERABILITY: Directory traversal in listing
    # User can list any directory: ?dir=../../../../etc/
    full_path = os.path.join(UPLOAD_FOLDER, directory)  # LINE 336: PATH TRAVERSAL - Directory listing
    
    try:
        # VULNERABILITY: Listing arbitrary directories
        files = os.listdir(full_path)  # LINE 340: ARBITRARY DIRECTORY LISTING
        
        file_info = []
        for f in files:
            file_path = os.path.join(full_path, f)
            if os.path.isfile(file_path):
                file_info.append({
                    'name': f,
                    'size': os.path.getsize(file_path),
                    'modified': os.path.getmtime(file_path)
                })
        
        return jsonify({
            'success': True,
            'directory': full_path,  # VULNERABILITY: Exposing full path
            'files': file_info
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/create_symlink', methods=['POST'])
def create_symlink():
    """Create symbolic link to a file"""
    data = request.get_json()
    source = data.get('source')
    link_name = data.get('link_name')
    
    if not source or not link_name:
        return jsonify({'error': 'Source and link name required'}), 400
    
    # VULNERABILITY: Creating symlinks with user-controlled paths
    # Can create symlinks to sensitive files, then access them through download endpoint
    source_path = os.path.join(UPLOAD_FOLDER, source)  # LINE 372: PATH TRAVERSAL
    link_path = os.path.join(UPLOAD_FOLDER, link_name)  # LINE 373: PATH TRAVERSAL
    
    try:
        # VULNERABILITY: Creating arbitrary symlinks
        os.symlink(source_path, link_path)  # LINE 377: SYMLINK CREATION TO ARBITRARY FILES
        return jsonify({'success': True, 'message': 'Symlink created'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    # VULNERABILITY: Path disclosure in error message
    return jsonify({
        'error': 'Resource not found',
        'path': request.path,  # LINE 388: PATH DISCLOSURE
        'method': request.method
    }), 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5003, debug=False)