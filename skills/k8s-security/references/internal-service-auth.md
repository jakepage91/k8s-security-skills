# Internal Service Authentication Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for securing service-to-service communication in Kubernetes, including authentication, mTLS, and JWT validation.

---

## Rule 1: Never Assume Internal Endpoints Are Safe

### NEVER

Skip authentication because an endpoint is "internal only."

```python
# WRONG - No auth because it's "internal"
@app.route('/internal/api/users')
def get_users():
    # "This is fine, it's only called by other services"
    # WRONG - any pod in the cluster can call this!
    return jsonify(get_all_users())

@app.route('/internal/api/admin/delete-all')
def delete_all():
    # WRONG - catastrophic if accessed by compromised pod
    delete_all_data()
    return '', 204
```

```yaml
# WRONG - Service assumes internal = safe
apiVersion: v1
kind: Service
metadata:
  name: internal-api
  annotations:
    description: "Internal API - no auth needed"  # DANGEROUS ASSUMPTION
spec:
  type: ClusterIP  # ClusterIP doesn't mean secure!
  ports:
  - port: 80
```

### ALWAYS

Authenticate all service-to-service communication.

```python
# CORRECT - Internal endpoints still require authentication
from functools import wraps
import jwt
import os

def require_service_auth(f):
    """Verify service-to-service JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Service-Token')
        if not token:
            return jsonify({'error': 'Missing service token'}), 401

        try:
            payload = jwt.decode(
                token,
                os.environ['SERVICE_JWT_SECRET'],
                algorithms=['HS256'],
                audience='internal-api'
            )
            # Verify the calling service is authorized
            if payload.get('service') not in ALLOWED_SERVICES:
                return jsonify({'error': 'Service not authorized'}), 403
            request.calling_service = payload.get('service')
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated

ALLOWED_SERVICES = ['frontend', 'worker', 'scheduler']

@app.route('/internal/api/users')
@require_service_auth
def get_users():
    # Now properly authenticated
    log.info(f"Request from service: {request.calling_service}")
    return jsonify(get_all_users())
```

---

## Rule 2: Always Validate Service Account Tokens or JWTs

### NEVER

Trust requests without cryptographic verification.

```python
# WRONG - Trusting a header without verification
@app.route('/internal/api/data')
def get_data():
    service_name = request.headers.get('X-Service-Name')
    if service_name in ['frontend', 'worker']:
        # WRONG - header can be spoofed by any pod!
        return jsonify(get_sensitive_data())
    return jsonify({'error': 'Forbidden'}), 403
```

```python
# WRONG - Not verifying token signature
@app.route('/internal/api/data')
def get_data():
    token = request.headers.get('Authorization')
    # WRONG - just checking token exists, not verifying it
    if token:
        return jsonify(get_sensitive_data())
    return jsonify({'error': 'Unauthorized'}), 401
```

### ALWAYS

Cryptographically verify tokens.

```python
# CORRECT - Verify Kubernetes ServiceAccount token
from kubernetes import client, config
import os

def verify_k8s_service_account_token(token: str) -> dict:
    """Verify a Kubernetes ServiceAccount token using TokenReview API."""
    config.load_incluster_config()
    auth_api = client.AuthenticationV1Api()

    token_review = client.V1TokenReview(
        spec=client.V1TokenReviewSpec(token=token)
    )
    response = auth_api.create_token_review(token_review)

    if not response.status.authenticated:
        raise ValueError("Token not authenticated")

    return {
        'username': response.status.user.username,
        'uid': response.status.user.uid,
        'groups': response.status.user.groups
    }

@app.route('/internal/api/data')
def get_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    try:
        user_info = verify_k8s_service_account_token(token)
        # Verify it's from an expected service account
        expected_sa = 'system:serviceaccount:production:frontend-sa'
        if user_info['username'] != expected_sa:
            return jsonify({'error': 'Unauthorized service'}), 403
    except Exception as e:
        return jsonify({'error': 'Token verification failed'}), 401

    return jsonify(get_sensitive_data())
```

```python
# CORRECT - Verify JWT with proper claims validation
import jwt
from jwt import PyJWKClient
import os

JWKS_URL = os.environ['JWKS_URL']
jwks_client = PyJWKClient(JWKS_URL)

def verify_service_jwt(token: str) -> dict:
    """Verify service-to-service JWT with full claims validation."""
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience='internal-api',
            issuer='https://auth.example.com',
            options={
                'require': ['exp', 'iat', 'aud', 'iss', 'sub'],
                'verify_exp': True,
                'verify_iat': True,
                'verify_aud': True,
                'verify_iss': True,
            }
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Token validation failed: {e}")

@app.route('/internal/api/data')
def get_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        claims = verify_service_jwt(token)
        # Additional authorization based on claims
        if claims.get('role') not in ['service', 'admin']:
            return jsonify({'error': 'Insufficient permissions'}), 403
    except ValueError as e:
        return jsonify({'error': str(e)}), 401

    return jsonify(get_sensitive_data())
```

---

## Rule 3: Use mTLS Where Service Mesh Supports It

### ALWAYS

Enable mTLS for service-to-service communication when using a service mesh.

```yaml
# CORRECT - Istio strict mTLS for namespace
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # Require mTLS for all services in namespace
```

```yaml
# CORRECT - Istio AuthorizationPolicy for service access
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: api-server-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-server
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/production/sa/frontend-sa
        - cluster.local/ns/production/sa/worker-sa
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*"]
```

```yaml
# CORRECT - Linkerd mTLS (enabled by default)
apiVersion: policy.linkerd.io/v1beta1
kind: Server
metadata:
  name: api-server
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  port: 8080
  proxyProtocol: HTTP/2
---
apiVersion: policy.linkerd.io/v1beta1
kind: ServerAuthorization
metadata:
  name: api-server-auth
  namespace: production
spec:
  server:
    name: api-server
  client:
    meshTLS:
      serviceAccounts:
      - name: frontend-sa
      - name: worker-sa
```

---

## Rule 4: Only /healthz and /readyz May Be Unauthenticated

### NEVER

Allow unauthenticated access to any endpoint except health probes.

```python
# WRONG - Multiple unauthenticated endpoints
@app.route('/metrics')  # WRONG - should be authenticated or restricted
def metrics():
    return generate_metrics()

@app.route('/debug/vars')  # WRONG - exposes internal state
def debug_vars():
    return jsonify(get_debug_info())

@app.route('/api/public')  # WRONG - "public" doesn't mean no auth
def public_api():
    return jsonify(get_data())
```

### ALWAYS

Restrict unauthenticated access to health endpoints only.

```python
# CORRECT - Only health probes are unauthenticated
from flask import Flask, jsonify, request
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not verify_request_auth(request):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# Health probes - NO authentication (for Kubernetes probes)
@app.route('/healthz')
def healthz():
    return jsonify({'status': 'healthy'})

@app.route('/readyz')
def readyz():
    if not check_dependencies():
        return jsonify({'status': 'not ready'}), 503
    return jsonify({'status': 'ready'})

# Metrics - REQUIRE authentication (or restrict via NetworkPolicy)
@app.route('/metrics')
@require_auth
def metrics():
    return generate_metrics()

# All other endpoints - REQUIRE authentication
@app.route('/api/data')
@require_auth
def get_data():
    return jsonify(fetch_data())
```

```yaml
# CORRECT - NetworkPolicy restricting metrics access
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-server-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
  - Ingress
  ingress:
  # Health probes from kubelet (node network)
  - ports:
    - protocol: TCP
      port: 8080
  # Metrics only from Prometheus
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
      podSelector:
        matchLabels:
          app: prometheus
    ports:
    - protocol: TCP
      port: 9090
```

---

## Rule 5: Implement Proper Service Identity

### ALWAYS

Use dedicated service accounts with proper RBAC for each service.

```yaml
# CORRECT - Dedicated ServiceAccount per service
apiVersion: v1
kind: ServiceAccount
metadata:
  name: frontend-sa
  namespace: production
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-server-sa
  namespace: production
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: production
```

```yaml
# CORRECT - Deployment with dedicated ServiceAccount
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: production
spec:
  template:
    spec:
      serviceAccountName: frontend-sa
      automountServiceAccountToken: true  # Only if needed for service-to-service auth
      containers:
      - name: frontend
        image: frontend:v1.0.0@sha256:abc123...
        env:
        # Service identity for outbound requests
        - name: SERVICE_NAME
          value: "frontend"
        - name: SERVICE_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
```

---

## Service-to-Service Authentication Patterns

### Pattern 1: Kubernetes ServiceAccount Tokens (Projected)

```yaml
# CORRECT - Use projected ServiceAccount token for service auth
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-client
spec:
  template:
    spec:
      serviceAccountName: api-client-sa
      containers:
      - name: client
        image: client:v1.0.0@sha256:abc123...
        volumeMounts:
        - name: service-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
      volumes:
      - name: service-token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
              audience: api-server  # Target service
```

```python
# CORRECT - Client using projected token
import requests
import os

def call_api_server():
    with open('/var/run/secrets/tokens/token', 'r') as f:
        token = f.read().strip()

    response = requests.get(
        'http://api-server.production.svc.cluster.local/api/data',
        headers={'Authorization': f'Bearer {token}'}
    )
    return response.json()
```

### Pattern 2: SPIFFE/SPIRE Identity

```yaml
# CORRECT - SPIRE agent sidecar for workload identity
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: api:v1.0.0@sha256:abc123...
        volumeMounts:
        - name: spiffe-workload-api
          mountPath: /run/spire/sockets
          readOnly: true
        env:
        - name: SPIFFE_ENDPOINT_SOCKET
          value: unix:///run/spire/sockets/agent.sock
      volumes:
      - name: spiffe-workload-api
        csi:
          driver: "csi.spiffe.io"
          readOnly: true
```

### Pattern 3: JWT with Shared Secret (Simpler Setup)

```python
# CORRECT - Service generates JWT for outbound requests
import jwt
import os
import time

def generate_service_token() -> str:
    """Generate a short-lived JWT for service-to-service calls."""
    payload = {
        'iss': os.environ['SERVICE_NAME'],
        'sub': os.environ['SERVICE_NAME'],
        'aud': 'internal-services',
        'iat': int(time.time()),
        'exp': int(time.time()) + 300,  # 5 minute expiry
    }
    return jwt.encode(payload, os.environ['SERVICE_JWT_SECRET'], algorithm='HS256')

def call_internal_service(url: str):
    token = generate_service_token()
    return requests.get(url, headers={'X-Service-Token': token})
```

```python
# CORRECT - Service validates incoming JWT
def verify_service_token(token: str) -> dict:
    """Verify incoming service-to-service JWT."""
    try:
        payload = jwt.decode(
            token,
            os.environ['SERVICE_JWT_SECRET'],
            algorithms=['HS256'],
            audience='internal-services',
            options={'require': ['iss', 'sub', 'aud', 'iat', 'exp']}
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")
```

---

## Pre-Commit Checklist for Internal Service Auth

- [ ] No endpoints trust "internal" status alone
- [ ] All service-to-service calls use authentication
- [ ] Tokens are cryptographically verified (not just checked for presence)
- [ ] mTLS enabled if using service mesh
- [ ] Only /healthz and /readyz are unauthenticated
- [ ] Each service has dedicated ServiceAccount
- [ ] Service identity verified in authentication
- [ ] Short-lived tokens used (< 1 hour expiry)
- [ ] Token audience/issuer claims validated
- [ ] NetworkPolicy restricts which services can communicate
