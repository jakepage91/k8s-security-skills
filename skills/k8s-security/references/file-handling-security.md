# File Handling & Path Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for secure file handling in Kubernetes applications, including path traversal prevention, input sanitization, and secure file upload handling.

---

## Rule 1: Always Sanitize Filenames from User Input

### NEVER

Use user-supplied filenames directly in file operations.

```python
# WRONG - Direct use of user filename
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # WRONG - allows path traversal!
    # Attacker can request: ?file=../../../etc/passwd
    return send_file(f'/uploads/{filename}')
```

```python
# WRONG - User filename in os.path.join
import os

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = file.filename  # User-controlled!
    # WRONG - path traversal via filename like "../../etc/cron.d/malicious"
    file.save(os.path.join('/uploads', filename))
    return 'Uploaded'
```

```javascript
// WRONG - Direct filename use
app.get('/files/:filename', (req, res) => {
  const filename = req.params.filename;
  // WRONG - attacker can use ..%2F..%2Fetc%2Fpasswd
  res.sendFile(path.join(__dirname, 'uploads', filename));
});
```

### ALWAYS

Sanitize and validate filenames before use.

```python
# CORRECT - Sanitize filename and validate path
import os
import re
from pathlib import Path
from werkzeug.utils import secure_filename

UPLOAD_DIR = Path('/uploads').resolve()

def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    # Remove path components
    filename = os.path.basename(filename)
    # Use werkzeug's secure_filename
    filename = secure_filename(filename)
    # Additional sanitization
    filename = re.sub(r'[^\w\-_\.]', '', filename)
    if not filename:
        raise ValueError("Invalid filename")
    return filename

def safe_join(base_dir: Path, filename: str) -> Path:
    """Safely join paths and verify result is within base directory."""
    safe_name = sanitize_filename(filename)
    full_path = (base_dir / safe_name).resolve()
    # Verify the path is within the allowed directory
    if not str(full_path).startswith(str(base_dir)):
        raise ValueError("Path traversal detected")
    return full_path

@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    try:
        safe_path = safe_join(UPLOAD_DIR, filename)
        if not safe_path.exists():
            return 'Not found', 404
        return send_file(safe_path)
    except ValueError as e:
        return str(e), 400

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file or not file.filename:
        return 'No file', 400

    try:
        safe_path = safe_join(UPLOAD_DIR, file.filename)
        file.save(safe_path)
        return 'Uploaded'
    except ValueError as e:
        return str(e), 400
```

```javascript
// CORRECT - Sanitize and validate paths
const path = require('path');
const sanitize = require('sanitize-filename');

const UPLOAD_DIR = path.resolve('/uploads');

function safeJoin(baseDir, filename) {
  // Sanitize the filename
  const safeName = sanitize(filename);
  if (!safeName) {
    throw new Error('Invalid filename');
  }

  // Resolve the full path
  const fullPath = path.resolve(baseDir, safeName);

  // Verify path is within base directory
  if (!fullPath.startsWith(baseDir + path.sep) && fullPath !== baseDir) {
    throw new Error('Path traversal detected');
  }

  return fullPath;
}

app.get('/files/:filename', (req, res) => {
  try {
    const safePath = safeJoin(UPLOAD_DIR, req.params.filename);
    res.sendFile(safePath);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

```go
// CORRECT - Go path sanitization
package handlers

import (
    "net/http"
    "path/filepath"
    "strings"
)

const uploadDir = "/uploads"

func SafeJoin(baseDir, filename string) (string, error) {
    // Clean the filename - removes .. and other dangerous components
    cleanName := filepath.Clean(filename)
    cleanName = filepath.Base(cleanName)  // Only keep the filename part

    if cleanName == "." || cleanName == ".." || cleanName == "" {
        return "", fmt.Errorf("invalid filename")
    }

    fullPath := filepath.Join(baseDir, cleanName)

    // Verify the path is within the base directory
    absBase, _ := filepath.Abs(baseDir)
    absPath, _ := filepath.Abs(fullPath)

    if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
        return "", fmt.Errorf("path traversal detected")
    }

    return fullPath, nil
}

func DownloadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")

    safePath, err := SafeJoin(uploadDir, filename)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    http.ServeFile(w, r, safePath)
}
```

```python
# CORRECT - FastAPI filename sanitization
import os
import re
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
UPLOAD_DIR = Path("/tmp/uploads").resolve()

def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\-_\.]', '', filename)
    if not filename:
        raise ValueError("Invalid filename")
    return filename

def safe_join(base_dir: Path, filename: str) -> Path:
    """Safely join paths and verify result is within base directory."""
    safe_name = sanitize_filename(filename)
    full_path = (base_dir / safe_name).resolve()
    if not str(full_path).startswith(str(base_dir)):
        raise ValueError("Path traversal detected")
    return full_path

@app.get("/download")
async def download_file(file: str):
    try:
        safe_path = safe_join(UPLOAD_DIR, file)
        if not safe_path.exists():
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(safe_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # file.filename is user-controlled - always sanitize
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    try:
        safe_path = safe_join(UPLOAD_DIR, file.filename)
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        safe_path.write_bytes(await file.read())
        return {"filename": safe_path.name}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

---

## Rule 2: Always Validate File Types and Sizes

### NEVER

Accept file uploads without validation.

```python
# WRONG - No validation
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    # No size limit - DoS via huge files
    # No type check - can upload .exe, .sh, etc.
    file.save(f'/uploads/{file.filename}')
    return 'OK'
```

### ALWAYS

Validate file type by content (magic bytes) and enforce size limits.

```python
# CORRECT - Comprehensive file validation
import magic
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_MIMETYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
}
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}

def validate_file(file) -> tuple[bool, str]:
    """Validate uploaded file."""
    # Check if file exists
    if not file or not file.filename:
        return False, "No file provided"

    # Check extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension {ext} not allowed"

    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to beginning

    if size > MAX_FILE_SIZE:
        return False, f"File too large: {size} bytes (max {MAX_FILE_SIZE})"

    if size == 0:
        return False, "Empty file"

    # Check actual content type (magic bytes)
    header = file.read(2048)
    file.seek(0)

    mime_type = magic.from_buffer(header, mime=True)
    if mime_type not in ALLOWED_MIMETYPES:
        return False, f"Content type {mime_type} not allowed"

    return True, "OK"

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')

    valid, message = validate_file(file)
    if not valid:
        return jsonify({'error': message}), 400

    try:
        safe_path = safe_join(UPLOAD_DIR, file.filename)
        file.save(safe_path)
        return jsonify({'message': 'Uploaded', 'path': safe_path.name})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
```

```javascript
// CORRECT - File validation with file-type library
const fileType = require('file-type');
const MAX_SIZE = 10 * 1024 * 1024;

const ALLOWED_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'application/pdf'
]);

async function validateFile(buffer, filename) {
  // Check size
  if (buffer.length > MAX_SIZE) {
    throw new Error(`File too large: ${buffer.length} bytes`);
  }

  if (buffer.length === 0) {
    throw new Error('Empty file');
  }

  // Check actual file type from magic bytes
  const type = await fileType.fromBuffer(buffer);
  if (!type || !ALLOWED_TYPES.has(type.mime)) {
    throw new Error(`File type not allowed: ${type?.mime || 'unknown'}`);
  }

  // Verify extension matches content
  const ext = path.extname(filename).toLowerCase();
  if (!type.ext || !ext.endsWith(type.ext)) {
    throw new Error('Extension does not match content type');
  }

  return type;
}
```

---

## Rule 3: Beware of Shared PersistentVolumeClaims

### NEVER

Allow user-controlled paths to access shared volumes.

```python
# WRONG - User can traverse to secrets mounted in same volume
@app.route('/read')
def read_file():
    path = request.args.get('path')
    # If PVC is mounted at /data and secrets at /data/secrets
    # User can request path=secrets/db-password
    with open(f'/data/{path}', 'r') as f:
        return f.read()
```

### ALWAYS

Strictly control access to shared storage and isolate sensitive data.

```python
# CORRECT - Isolated directories with strict validation
import os
from pathlib import Path

# Define separate mount points for different purposes
USER_DATA_DIR = Path('/data/user-files').resolve()
APP_CONFIG_DIR = Path('/data/config').resolve()
# Secrets should be in separate volume: /secrets

def read_user_file(filename: str) -> str:
    """Read a user file from the designated user directory only."""
    safe_name = sanitize_filename(filename)
    file_path = (USER_DATA_DIR / safe_name).resolve()

    # Strict boundary check
    if not str(file_path).startswith(str(USER_DATA_DIR) + '/'):
        raise PermissionError("Access denied")

    if not file_path.exists():
        raise FileNotFoundError("File not found")

    with open(file_path, 'r') as f:
        return f.read()

@app.route('/read')
def read_file():
    try:
        filename = request.args.get('file', '')
        content = read_user_file(filename)
        return content
    except (PermissionError, FileNotFoundError) as e:
        return str(e), 404
    except ValueError as e:
        return str(e), 400
```

```yaml
# CORRECT - Separate volumes for user data and secrets
apiVersion: apps/v1
kind: Deployment
metadata:
  name: file-server
spec:
  template:
    spec:
      containers:
      - name: app
        image: file-server:v1.0.0@sha256:abc123...
        volumeMounts:
        # User data - may be accessible via API
        - name: user-data
          mountPath: /data/user-files
        # Secrets - never accessible via file API
        - name: secrets
          mountPath: /secrets
          readOnly: true
        # Temp - for processing
        - name: tmp
          mountPath: /tmp
        securityContext:
          readOnlyRootFilesystem: true
      volumes:
      # Separate PVC for user data
      - name: user-data
        persistentVolumeClaim:
          claimName: user-data-pvc
      # Secrets from Secret resource
      - name: secrets
        secret:
          secretName: app-secrets
          defaultMode: 0400
      # Ephemeral temp storage
      - name: tmp
        emptyDir:
          sizeLimit: 100Mi
```

---

## Rule 4: Secure File Upload Implementation

### ALWAYS

Implement comprehensive upload security.

```python
# CORRECT - Complete secure file upload
import os
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
import magic

class SecureFileHandler:
    def __init__(self, upload_dir: str, max_size: int = 10*1024*1024):
        self.upload_dir = Path(upload_dir).resolve()
        self.max_size = max_size
        self.upload_dir.mkdir(parents=True, exist_ok=True)

        self.allowed_types = {
            'image/jpeg': ['.jpg', '.jpeg'],
            'image/png': ['.png'],
            'image/gif': ['.gif'],
            'application/pdf': ['.pdf'],
        }

    def _generate_safe_filename(self, original_name: str, content_type: str) -> str:
        """Generate a safe filename that prevents collisions and traversal."""
        # Get allowed extension for content type
        extensions = self.allowed_types.get(content_type, [])
        ext = extensions[0] if extensions else '.bin'

        # Generate unique filename
        unique_id = uuid.uuid4().hex[:12]
        timestamp = datetime.utcnow().strftime('%Y%m%d')

        return f"{timestamp}_{unique_id}{ext}"

    def _validate_content(self, data: bytes) -> str:
        """Validate file content and return MIME type."""
        if len(data) == 0:
            raise ValueError("Empty file")

        if len(data) > self.max_size:
            raise ValueError(f"File exceeds maximum size of {self.max_size} bytes")

        mime_type = magic.from_buffer(data, mime=True)

        if mime_type not in self.allowed_types:
            raise ValueError(f"File type '{mime_type}' not allowed")

        return mime_type

    def _compute_checksum(self, data: bytes) -> str:
        """Compute SHA-256 checksum of file data."""
        return hashlib.sha256(data).hexdigest()

    def save(self, file) -> dict:
        """Securely save an uploaded file."""
        if not file or not file.filename:
            raise ValueError("No file provided")

        # Read content
        data = file.read()

        # Validate content
        mime_type = self._validate_content(data)

        # Generate safe filename
        safe_filename = self._generate_safe_filename(file.filename, mime_type)

        # Save file
        file_path = self.upload_dir / safe_filename
        with open(file_path, 'wb') as f:
            f.write(data)

        # Set restrictive permissions
        os.chmod(file_path, 0o644)

        return {
            'filename': safe_filename,
            'original_name': secure_filename(file.filename),
            'size': len(data),
            'mime_type': mime_type,
            'checksum': self._compute_checksum(data),
        }

    def get_safe_path(self, filename: str) -> Path:
        """Get the safe path for a file, preventing traversal."""
        # Only allow our generated filenames
        if not filename or '/' in filename or '\\' in filename:
            raise ValueError("Invalid filename")

        # Additional validation - must match our filename pattern
        if not filename[0].isdigit():
            raise ValueError("Invalid filename format")

        file_path = (self.upload_dir / filename).resolve()

        # Verify path is within upload directory
        if not str(file_path).startswith(str(self.upload_dir) + '/'):
            raise ValueError("Path traversal detected")

        return file_path


# Usage
upload_handler = SecureFileHandler('/uploads')

@app.route('/upload', methods=['POST'])
def upload():
    try:
        file = request.files.get('file')
        result = upload_handler.save(file)
        return jsonify(result)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/download/<filename>')
def download(filename):
    try:
        safe_path = upload_handler.get_safe_path(filename)
        if not safe_path.exists():
            return 'Not found', 404
        return send_file(safe_path)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
```

```python
# CORRECT - FastAPI secure file upload (UploadFile)
import os
import uuid
import hashlib
import magic
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()

UPLOAD_DIR = Path("/tmp/uploads").resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# For a document ingestion use case, allow text/plain and PDF
ALLOWED_MIMETYPES = {
    "text/plain": [".txt"],
    "application/pdf": [".pdf"],
    "text/markdown": [".md"],
}

def _validate_and_save(data: bytes, original_name: str) -> dict:
    """Validate content and save with a generated safe filename."""
    if len(data) == 0:
        raise ValueError("Empty file")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds {MAX_FILE_SIZE} bytes")

    mime_type = magic.from_buffer(data, mime=True)
    if mime_type not in ALLOWED_MIMETYPES:
        raise ValueError(f"File type '{mime_type}' not allowed")

    ext = ALLOWED_MIMETYPES[mime_type][0]
    safe_name = f"{datetime.utcnow().strftime('%Y%m%d')}_{uuid.uuid4().hex[:12]}{ext}"

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / safe_name
    dest.write_bytes(data)
    os.chmod(dest, 0o644)

    return {
        "filename": safe_name,
        "size": len(data),
        "mime_type": mime_type,
        "checksum": hashlib.sha256(data).hexdigest(),
    }

@app.post("/v1/documents")
async def upload_document(file: UploadFile = File(...)):
    """Accept a document upload for LLM ingestion."""
    try:
        data = await file.read()
        result = _validate_and_save(data, file.filename or "")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/v1/documents/{filename}")
async def download_document(filename: str):
    # Only allow our generated filenames (starts with a digit, no slashes)
    if not filename or not filename[0].isdigit() or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    safe_path = (UPLOAD_DIR / filename).resolve()
    if not str(safe_path).startswith(str(UPLOAD_DIR)):
        raise HTTPException(status_code=400, detail="Path traversal detected")
    if not safe_path.exists():
        raise HTTPException(status_code=404, detail="Not found")

    return FileResponse(safe_path)
```

---

## Rule 5: Temporary File Security

### NEVER

Create temporary files with predictable names or insecure permissions.

```python
# WRONG - Predictable temp file
import os

def process_upload(data):
    # WRONG - predictable filename, race condition
    tmp_path = '/tmp/upload.tmp'
    with open(tmp_path, 'wb') as f:
        f.write(data)
    process_file(tmp_path)
    os.remove(tmp_path)
```

### ALWAYS

Use secure temporary file handling.

```python
# CORRECT - Secure temporary file handling
import tempfile
import os

def process_upload(data: bytes) -> dict:
    """Process upload using secure temporary file."""
    # Create secure temp file with restricted permissions
    fd, tmp_path = tempfile.mkstemp(prefix='upload_', suffix='.tmp')
    try:
        # Set restrictive permissions
        os.chmod(tmp_path, 0o600)

        # Write data
        with os.fdopen(fd, 'wb') as f:
            f.write(data)

        # Process file
        result = process_file(tmp_path)
        return result
    finally:
        # Always clean up
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

# Or use context manager
def process_upload_v2(data: bytes) -> dict:
    """Process upload using temp file context manager."""
    with tempfile.NamedTemporaryFile(
        mode='wb',
        prefix='upload_',
        suffix='.tmp',
        delete=True  # Auto-delete on close
    ) as tmp:
        tmp.write(data)
        tmp.flush()
        return process_file(tmp.name)
```

---

## Pre-Commit Checklist for File Handling Security

- [ ] All user-supplied filenames are sanitized
- [ ] Path traversal prevention implemented (resolve + prefix check)
- [ ] File types validated by magic bytes, not just extension
- [ ] File size limits enforced before reading full content
- [ ] Uploaded files saved with generated names, not user names
- [ ] Uploaded files have restrictive permissions (0644 or 0600)
- [ ] Temp files use secure creation (tempfile module)
- [ ] Temp files cleaned up in finally blocks
- [ ] Shared PVCs have isolated directories for user vs system data
- [ ] Secrets never accessible via file download APIs
- [ ] File checksums computed for integrity verification
