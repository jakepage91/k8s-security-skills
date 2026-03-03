# Secrets Management Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for handling secrets in Kubernetes environments, including API keys, database credentials, TLS certificates, OAuth tokens, and webhook signing secrets.

---

## Rule 1: Never Hardcode Secrets in Source Code

### NEVER

Hardcode secrets directly in application code, configuration files, or environment variable defaults.

```python
# WRONG - Hardcoded API key
import requests

API_KEY = "sk-1234567890abcdef"  # NEVER DO THIS
response = requests.get(
    "https://api.example.com/data",
    headers={"Authorization": f"Bearer {API_KEY}"}
)
```

```javascript
// WRONG - Hardcoded database credentials
const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'db.example.com',
  user: 'admin',           // NEVER DO THIS
  password: 'SuperSecret123!',  // NEVER DO THIS
  database: 'production'
});
```

```go
// WRONG - Hardcoded OAuth token
package main

const oauthToken = "ghp_xxxxxxxxxxxxxxxxxxxx" // NEVER DO THIS
```

### ALWAYS

Read secrets from environment variables or mounted Kubernetes Secrets.

```python
# CORRECT - Read from environment variable
import os
import requests

API_KEY = os.environ["API_KEY"]  # Fails fast if not set
response = requests.get(
    "https://api.example.com/data",
    headers={"Authorization": f"Bearer {API_KEY}"}
)
```

```javascript
// CORRECT - Read from environment variable
const mysql = require('mysql');

if (!process.env.DB_PASSWORD) {
  throw new Error('DB_PASSWORD environment variable is required');
}

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});
```

```go
// CORRECT - Read from environment variable with validation
package main

import (
    "log"
    "os"
)

func main() {
    oauthToken := os.Getenv("OAUTH_TOKEN")
    if oauthToken == "" {
        log.Fatal("OAUTH_TOKEN environment variable is required")
    }
    // Use oauthToken...
}
```

---

## Rule 2: Fail-Fast at Startup for Missing Secrets

### NEVER

Continue application startup with None/null/empty values for required secrets.

```python
# WRONG - Continues with None, will fail later at runtime
import os

API_KEY = os.getenv("API_KEY")  # Returns None if not set
# Application continues, crashes later when API_KEY is used
```

```javascript
// WRONG - No validation, undefined propagates
const apiKey = process.env.API_KEY;
// Application starts, fails mysteriously later
```

### ALWAYS

Validate all required secrets at startup and fail immediately if any are missing.

```python
# CORRECT - Fail-fast validation at startup
import os
import sys

REQUIRED_SECRETS = [
    "API_KEY",
    "DB_PASSWORD",
    "JWT_SECRET",
    "WEBHOOK_SIGNING_KEY",
]

def validate_secrets():
    missing = [s for s in REQUIRED_SECRETS if not os.environ.get(s)]
    if missing:
        print(f"FATAL: Missing required secrets: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

# Call at module load time
validate_secrets()

# Now safe to use
API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

```javascript
// CORRECT - Fail-fast validation at startup
const REQUIRED_SECRETS = [
  'API_KEY',
  'DB_PASSWORD',
  'JWT_SECRET',
  'WEBHOOK_SIGNING_KEY',
];

function validateSecrets() {
  const missing = REQUIRED_SECRETS.filter(key => !process.env[key]);
  if (missing.length > 0) {
    console.error(`FATAL: Missing required secrets: ${missing.join(', ')}`);
    process.exit(1);
  }
}

validateSecrets();

// Now safe to use
const { API_KEY, DB_PASSWORD, JWT_SECRET } = process.env;
```

```go
// CORRECT - Fail-fast validation at startup
package config

import (
    "fmt"
    "log"
    "os"
)

type Config struct {
    APIKey           string
    DBPassword       string
    JWTSecret        string
    WebhookSigningKey string
}

func LoadConfig() *Config {
    required := map[string]*string{
        "API_KEY":             new(string),
        "DB_PASSWORD":         new(string),
        "JWT_SECRET":          new(string),
        "WEBHOOK_SIGNING_KEY": new(string),
    }

    var missing []string
    for key, ptr := range required {
        *ptr = os.Getenv(key)
        if *ptr == "" {
            missing = append(missing, key)
        }
    }

    if len(missing) > 0 {
        log.Fatalf("FATAL: Missing required secrets: %v", missing)
    }

    return &Config{
        APIKey:           *required["API_KEY"],
        DBPassword:       *required["DB_PASSWORD"],
        JWTSecret:        *required["JWT_SECRET"],
        WebhookSigningKey: *required["WEBHOOK_SIGNING_KEY"],
    }
}
```

---

## Rule 3: Never Log Secret Values

### NEVER

Log secret values at any log level, including debug.

```python
# WRONG - Logging secret value
import logging

logging.debug(f"Using API key: {api_key}")  # NEVER DO THIS
logging.info(f"Connecting with password: {db_password}")  # NEVER DO THIS
logging.error(f"Auth failed for token: {jwt_token}")  # NEVER DO THIS
```

```javascript
// WRONG - Logging secrets
console.log(`API Key: ${apiKey}`);  // NEVER DO THIS
console.debug(`OAuth token: ${token}`);  // NEVER DO THIS
logger.info({ password: dbPassword });  // NEVER DO THIS
```

### ALWAYS

Log only that a secret was used, never its value. Use redaction for structured logging.

```python
# CORRECT - Log presence, not value
import logging

logging.debug("API key configured: %s", "***" if api_key else "NOT SET")
logging.info("Database connection configured with provided credentials")
logging.error("Authentication failed for user: %s", username)  # Log user, not token
```

```javascript
// CORRECT - Redact secrets in structured logging
const redactSecrets = (obj) => {
  const redacted = { ...obj };
  const sensitiveKeys = ['password', 'token', 'apiKey', 'secret', 'credential'];
  for (const key of Object.keys(redacted)) {
    if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
      redacted[key] = '[REDACTED]';
    }
  }
  return redacted;
};

logger.info('Request received', redactSecrets(requestData));
```

---

## Rule 4: Never Include Secrets in Error Messages or HTTP Responses

### NEVER

Include secret values in error messages, exceptions, or API responses.

```python
# WRONG - Secret in error message
raise ValueError(f"Invalid API key: {api_key}")  # NEVER DO THIS

# WRONG - Secret in HTTP response
return {"error": f"Database auth failed with password: {password}"}  # NEVER
```

```javascript
// WRONG - Secret in error
throw new Error(`Invalid token: ${token}`);  // NEVER DO THIS

// WRONG - Secret in response
res.status(401).json({ error: `Bad API key: ${apiKey}` });  // NEVER DO THIS
```

### ALWAYS

Return generic error messages. Log details server-side with redaction.

```python
# CORRECT - Generic error, detailed server-side logging
import logging
import uuid

def authenticate(api_key):
    if not is_valid(api_key):
        error_id = str(uuid.uuid4())
        logging.warning("Auth failed, error_id=%s, key_prefix=%s",
                       error_id, api_key[:4] + "..." if api_key else "empty")
        raise AuthenticationError(f"Authentication failed. Reference: {error_id}")
```

```javascript
// CORRECT - Generic error response
app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();
  logger.error({ errorId, type: err.name, path: req.path });  // No secrets
  res.status(500).json({
    error: 'Internal server error',
    reference: errorId
  });
});
```

---

## Rule 5: Use Kubernetes Secrets Correctly

### NEVER

Inline secret values in Kubernetes manifests that will be committed to git.

```yaml
# WRONG - Hardcoded secret in Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        env:
        - name: API_KEY
          value: "sk-1234567890abcdef"  # NEVER DO THIS
        - name: DB_PASSWORD
          value: "SuperSecret123!"      # NEVER DO THIS
```

```yaml
# WRONG - Secret value in ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  API_KEY: "sk-1234567890abcdef"  # NEVER - ConfigMaps are not for secrets
```

### ALWAYS

Use `secretKeyRef` to reference Kubernetes Secrets. Create Secrets separately (not in git).

```yaml
# CORRECT - Reference secrets using secretKeyRef
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-credentials
              key: api-key
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
```

```yaml
# CORRECT - Secret manifest template (values injected by CI/CD or external secrets operator)
# This file defines structure only - actual values come from:
# - External Secrets Operator (AWS Secrets Manager, HashiCorp Vault, etc.)
# - CI/CD pipeline injection
# - Manual kubectl create secret command
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
  annotations:
    description: "API credentials - values managed externally"
type: Opaque
stringData:
  api-key: "${API_KEY}"  # Placeholder - replaced by CI/CD
  # OR use External Secrets Operator
---
# Using External Secrets Operator (preferred for production)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: api-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: api-credentials
  data:
  - secretKey: api-key
    remoteRef:
      key: production/api-credentials
      property: api-key
```

---

## Rule 6: Mount Secrets as Files for TLS Certificates

### NEVER

Pass TLS certificates/keys through environment variables (size limits, encoding issues).

```yaml
# WRONG - TLS cert in environment variable
env:
- name: TLS_CERT
  valueFrom:
    secretKeyRef:
      name: tls-secret
      key: tls.crt  # Certificates should be mounted as files
```

### ALWAYS

Mount TLS certificates and keys as files with restricted permissions.

```yaml
# CORRECT - Mount TLS secrets as files
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/tls
          readOnly: true
        env:
        - name: TLS_CERT_PATH
          value: /etc/tls/tls.crt
        - name: TLS_KEY_PATH
          value: /etc/tls/tls.key
      volumes:
      - name: tls-certs
        secret:
          secretName: api-tls-secret
          defaultMode: 0400  # Read-only for owner
```

```python
# CORRECT - Read TLS cert from mounted file
import os
import ssl

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(
    certfile=os.environ["TLS_CERT_PATH"],
    keyfile=os.environ["TLS_KEY_PATH"]
)
```

---

## Rule 7: Rotate Secrets Without Downtime

### ALWAYS

Design applications to handle secret rotation gracefully.

```python
# CORRECT - Reload secrets periodically or on signal
import os
import signal
import threading

class SecretManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._secrets = {}
        self._load_secrets()
        signal.signal(signal.SIGHUP, self._handle_reload)

    def _load_secrets(self):
        with self._lock:
            self._secrets = {
                'api_key': os.environ.get('API_KEY'),
                'db_password': os.environ.get('DB_PASSWORD'),
            }

    def _handle_reload(self, signum, frame):
        self._load_secrets()

    def get(self, key):
        with self._lock:
            return self._secrets.get(key)

secrets = SecretManager()
```

---

## Covered Secret Types Checklist

| Secret Type | Storage | Injection Method | Rotation Strategy |
|-------------|---------|------------------|-------------------|
| API Keys | K8s Secret / External Secrets | `secretKeyRef` env var | Reload on SIGHUP |
| Database Credentials | K8s Secret / Vault | `secretKeyRef` env var | Connection pool refresh |
| TLS Certificates | K8s Secret (tls type) | Volume mount | Certificate manager auto-renewal |
| OAuth Tokens | K8s Secret / External Secrets | `secretKeyRef` env var | Token refresh in code |
| Webhook Signing Secrets | K8s Secret | `secretKeyRef` env var | Dual-key verification during rotation |
| JWT Signing Keys | K8s Secret / Vault | Volume mount | Key ID (kid) based selection |

---

## Pre-Commit Checklist for Secrets

- [ ] No hardcoded secrets in source code
- [ ] No secrets in ConfigMaps
- [ ] All secrets use `secretKeyRef` or volume mounts
- [ ] Application fails fast on missing secrets
- [ ] No secrets in log output
- [ ] No secrets in error messages/HTTP responses
- [ ] TLS certs mounted as files (not env vars)
- [ ] Secret manifests use placeholders (not real values)
- [ ] `.gitignore` includes `*.pem`, `*.key`, `secrets.yaml`, `.env*`
