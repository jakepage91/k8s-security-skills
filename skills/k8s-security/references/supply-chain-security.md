# Supply Chain Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for securing the software supply chain, including dependency management, container images, and Dockerfile security.

---

## Rule 1: Always Pin Dependency Versions Exactly

### NEVER

Use version ranges, caret (^), tilde (~), or unpinned dependencies.

```json
// WRONG - package.json with ranges
{
  "dependencies": {
    "express": "^4.18.0",     // WRONG - caret allows minor/patch updates
    "lodash": "~4.17.0",      // WRONG - tilde allows patch updates
    "axios": "*",             // WRONG - any version
    "moment": "latest"        // WRONG - latest tag
  }
}
```

```txt
# WRONG - requirements.txt with ranges
Flask>=2.0.0           # WRONG - any version >= 2.0.0
requests~=2.28.0       # WRONG - compatible release
django                 # WRONG - unpinned
SQLAlchemy>=1.4,<2.0   # WRONG - version range
```

```toml
# WRONG - Cargo.toml with ranges
[dependencies]
serde = "1"            # WRONG - any 1.x.x
tokio = "^1.0"         # WRONG - caret
```

```mod
// WRONG - go.mod without checksums
require (
    github.com/gin-gonic/gin v1.9.0  // WRONG - no checksum in go.sum
)
```

### ALWAYS

Pin every dependency to an exact version with integrity hashes where possible.

```json
// CORRECT - package.json with exact versions
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.2"
  }
}
// Also use package-lock.json or yarn.lock with integrity hashes
```

```txt
# CORRECT - requirements.txt with exact versions and hashes
Flask==2.3.3 \
    --hash=sha256:1234567890abcdef...
requests==2.31.0 \
    --hash=sha256:abcdef1234567890...
django==4.2.7 \
    --hash=sha256:fedcba0987654321...
SQLAlchemy==2.0.23 \
    --hash=sha256:9876543210fedcba...
```

```toml
# CORRECT - Cargo.toml with exact versions
[dependencies]
serde = "=1.0.193"
tokio = "=1.35.0"
# Cargo.lock provides additional integrity
```

```mod
// CORRECT - go.mod with specific versions
require (
    github.com/gin-gonic/gin v1.9.1
)
// go.sum provides checksums automatically
```

---

## Rule 2: Always Use Digest-Pinned Base Images

### NEVER

Use `:latest` tag or unpinned image references.

```dockerfile
# WRONG - Latest tag
FROM python:latest

# WRONG - Version tag without digest (can change)
FROM python:3.12-slim

# WRONG - No tag at all (defaults to latest)
FROM node

# WRONG - Even specific version can be overwritten
FROM golang:1.21.5
```

### ALWAYS

Pin images by digest (sha256).

```dockerfile
# CORRECT - Digest-pinned image
FROM python:3.12-slim@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# CORRECT - Official image with digest
FROM node:20-alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# CORRECT - Multi-stage with digest pinning
FROM golang:1.21.5@sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 AS builder
# ... build steps ...

FROM gcr.io/distroless/static-debian12@sha256:9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef
COPY --from=builder /app/binary /app/binary
```

```yaml
# CORRECT - Kubernetes manifest with digest
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: api
        image: myregistry.io/myapp:v1.2.3@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

---

## Rule 3: Never Use curl | bash Install Patterns

### NEVER

Download and execute scripts in a single command.

```dockerfile
# WRONG - curl | bash (unverified code execution)
RUN curl -fsSL https://example.com/install.sh | bash

# WRONG - wget | sh
RUN wget -qO- https://get.example.com | sh

# WRONG - Even with HTTPS, content can change
RUN curl https://raw.githubusercontent.com/example/repo/main/install.sh | bash

# WRONG - Hidden in multi-line
RUN apt-get update && \
    curl -fsSL https://deb.example.com/setup | bash - && \
    apt-get install -y example-package
```

### ALWAYS

Download scripts, verify integrity, then execute separately.

```dockerfile
# CORRECT - Download, verify, then execute
RUN curl -fsSL -o /tmp/install.sh https://example.com/install.sh && \
    echo "expected_sha256_hash  /tmp/install.sh" | sha256sum -c - && \
    chmod +x /tmp/install.sh && \
    /tmp/install.sh && \
    rm /tmp/install.sh

# CORRECT - Use package managers when possible
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# CORRECT - Copy from builder stage instead of runtime downloads
FROM golang:1.21@sha256:abc... AS builder
RUN go install github.com/example/tool@v1.2.3

FROM gcr.io/distroless/static@sha256:def...
COPY --from=builder /go/bin/tool /usr/local/bin/tool
```

---

## Rule 4: Always Use Multi-Stage Builds

### NEVER

Ship build tools, source code, or development dependencies in production images.

```dockerfile
# WRONG - Build tools in production image
FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Image contains: pip, setuptools, git, gcc, source code, tests, etc.
CMD ["python", "app.py"]
```

```dockerfile
# WRONG - Node build tools in production
FROM node:20
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
# Image contains: npm, node_modules with devDependencies, TypeScript, etc.
CMD ["node", "dist/index.js"]
```

### ALWAYS

Use multi-stage builds to separate build and runtime environments.

```dockerfile
# CORRECT - Multi-stage Python build
FROM python:3.12-slim@sha256:abc123... AS builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.12-slim@sha256:abc123...
WORKDIR /app

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Copy only installed packages
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

# Copy only application code
COPY --chown=appuser:appuser app/ ./app/

CMD ["python", "-m", "app.main"]
```

```dockerfile
# CORRECT - Multi-stage Node build
FROM node:20-alpine@sha256:def456... AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage with minimal image
FROM node:20-alpine@sha256:def456...
WORKDIR /app

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Copy only production dependencies and built code
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/package.json ./

CMD ["node", "dist/index.js"]
```

```dockerfile
# CORRECT - Multi-stage Go build (distroless final image)
FROM golang:1.21@sha256:abc123... AS builder
WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/server ./cmd/server

# Minimal production image
FROM gcr.io/distroless/static-debian12@sha256:def456...

COPY --from=builder /app/server /server

USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

---

## Rule 5: Always Run as Non-Root User

### NEVER

Run containers as root.

```dockerfile
# WRONG - No USER directive (runs as root)
FROM python:3.12-slim
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
# Container runs as root!
```

```dockerfile
# WRONG - Explicitly running as root
FROM node:20
USER root
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

### ALWAYS

Create and use a non-root user.

```dockerfile
# CORRECT - Create and use non-root user
FROM python:3.12-slim@sha256:abc123...
WORKDIR /app

# Create non-root user
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Install dependencies as root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app with correct ownership
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

CMD ["python", "app.py"]
```

```dockerfile
# CORRECT - Alpine with non-root user
FROM node:20-alpine@sha256:def456...
WORKDIR /app

# Create non-root user (Alpine syntax)
RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

COPY --chown=appuser:appgroup package*.json ./
RUN npm ci --only=production

COPY --chown=appuser:appgroup . .

USER appuser
CMD ["node", "index.js"]
```

---

## Rule 6: Always Minimize Image Size and Attack Surface

### NEVER

Include unnecessary tools, packages, or files.

```dockerfile
# WRONG - Full OS with unnecessary packages
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    vim \
    git \
    ssh \
    netcat \
    telnet
```

### ALWAYS

Use minimal base images and remove unnecessary files.

```dockerfile
# CORRECT - Minimal image with only required packages
FROM python:3.12-slim@sha256:abc123...
WORKDIR /app

# Install only required packages, clean up in same layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Don't copy unnecessary files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Use .dockerignore to exclude files
COPY app/ ./app/

USER 1000
CMD ["python", "-m", "app.main"]
```

```dockerfile
# CORRECT - Distroless for Go (minimal attack surface)
FROM gcr.io/distroless/static-debian12@sha256:abc123...
# Contains: timezone data, CA certs, /etc/passwd with nobody user
# Does NOT contain: shell, package manager, any other binaries

COPY --from=builder /app/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

---

## .dockerignore Template

```
# CORRECT - Comprehensive .dockerignore
# Git
.git
.gitignore

# CI/CD
.github
.gitlab-ci.yml
Jenkinsfile
.circleci

# IDE
.idea
.vscode
*.swp
*.swo

# Documentation
*.md
!README.md
docs/

# Tests
tests/
test/
*_test.go
*_test.py
*.test.js
*.spec.js
__tests__/
coverage/
.coverage
htmlcov/

# Build artifacts
dist/
build/
*.egg-info/
node_modules/
vendor/

# Environment and secrets
.env
.env.*
*.pem
*.key
secrets/

# Docker
Dockerfile*
docker-compose*.yml
.dockerignore

# Misc
*.log
*.tmp
.DS_Store
Thumbs.db
```

---

## Language-Specific Examples

### Python (pip)

```txt
# requirements.txt - CORRECT
# Generated with: pip-compile --generate-hashes requirements.in
Flask==2.3.3 \
    --hash=sha256:09c347a92aa7ff4a8e7f3206795f30d826654baf38b873d0744cd571ca609efc \
    --hash=sha256:f69fcd559dc907ed196ab9df0e48471709175e696d6e698dd4dbe940f96ce66b
Werkzeug==3.0.1 \
    --hash=sha256:507e811ecea72b18a404947ead4b3c2fb1ed0c809ce9b5a31df2d1cddbcbf68e \
    --hash=sha256:90a285dc0e42ad56b34e696398b8122ee4c681833fb35b8334a095d82c56da10
```

### Node.js (npm)

```json
// package.json - CORRECT
{
  "dependencies": {
    "express": "4.18.2",
    "helmet": "7.1.0"
  },
  "devDependencies": {
    "typescript": "5.3.3"
  },
  "engines": {
    "node": "20.10.0",
    "npm": "10.2.5"
  }
}
// ALWAYS commit package-lock.json
```

### Go (modules)

```mod
// go.mod - CORRECT
module myapp

go 1.21.5

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
)
// go.sum is auto-generated with checksums - ALWAYS commit it
```

### Rust (Cargo)

```toml
# Cargo.toml - CORRECT
[dependencies]
tokio = "=1.35.0"
serde = "=1.0.193"
# Cargo.lock provides integrity - ALWAYS commit it for applications
```

---

## Pre-Commit Checklist for Supply Chain Security

- [ ] All dependencies pinned to exact versions
- [ ] Lock files (package-lock.json, go.sum, Cargo.lock) committed
- [ ] Dependency hashes verified where supported
- [ ] Base images pinned by digest (sha256)
- [ ] No `:latest` or unpinned image tags
- [ ] No `curl | bash` patterns in Dockerfile
- [ ] Multi-stage build used
- [ ] Final image runs as non-root user
- [ ] .dockerignore excludes secrets, tests, docs
- [ ] No build tools in production image
- [ ] Minimal base image (slim, alpine, or distroless)
- [ ] No secrets in image layers
