# Network Exposure & Ingress Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for network security in Kubernetes, including Services, Ingress, NetworkPolicies, webhook verification, and rate limiting.

---

## Rule 1: Always Add Authentication to HTTP Endpoints

### NEVER

Expose HTTP endpoints without authentication (except health checks).

```python
# WRONG - Unauthenticated endpoint
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/users')
def get_users():
    # No authentication - anyone can access!
    return jsonify(get_all_users())

@app.route('/api/admin/delete-user', methods=['POST'])
def delete_user():
    # No authentication on admin endpoint!
    return jsonify(delete_user_by_id(request.json['id']))
```

```javascript
// WRONG - No authentication middleware
app.get('/api/data', (req, res) => {
  // Anyone can access this endpoint
  res.json(sensitiveData);
});
```

### ALWAYS

Require authentication on all endpoints except /healthz and /readyz.

```python
# CORRECT - Authentication required
from flask import Flask, jsonify, request
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token or not validate_jwt(token):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# Health endpoints - NO authentication (for k8s probes)
@app.route('/healthz')
def healthz():
    return jsonify({'status': 'healthy'})

@app.route('/readyz')
def readyz():
    if not check_dependencies():
        return jsonify({'status': 'not ready'}), 503
    return jsonify({'status': 'ready'})

# All other endpoints - REQUIRE authentication
@app.route('/api/users')
@require_auth
def get_users():
    return jsonify(get_all_users())

@app.route('/api/admin/delete-user', methods=['POST'])
@require_auth
@require_role('admin')  # Additional role check for sensitive operations
def delete_user():
    return jsonify(delete_user_by_id(request.json['id']))
```

```javascript
// CORRECT - Authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Health endpoints - no auth
app.get('/healthz', (req, res) => res.json({ status: 'healthy' }));
app.get('/readyz', (req, res) => res.json({ status: 'ready' }));

// All API routes require authentication
app.use('/api', authenticateJWT);
app.get('/api/data', (req, res) => {
  res.json(getData(req.user.id));
});
```

---

## Rule 2: Always Verify Webhook Signatures

### NEVER

Accept webhook payloads without signature verification.

```python
# WRONG - No signature verification
@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    # Accepting any payload - attacker can forge requests!
    event = request.json
    process_stripe_event(event)
    return '', 200

@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    # No signature check!
    payload = request.json
    process_github_event(payload)
    return '', 200
```

### ALWAYS

Verify webhook signatures before processing.

```python
# CORRECT - Stripe webhook signature verification
import stripe
import os

@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.environ['STRIPE_WEBHOOK_SECRET']

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 401

    process_stripe_event(event)
    return '', 200
```

```python
# CORRECT - GitHub webhook signature verification
import hmac
import hashlib
import os

@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return jsonify({'error': 'Missing signature'}), 401

    webhook_secret = os.environ['GITHUB_WEBHOOK_SECRET'].encode()
    expected_sig = 'sha256=' + hmac.new(
        webhook_secret,
        request.data,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return jsonify({'error': 'Invalid signature'}), 401

    payload = request.json
    process_github_event(payload)
    return '', 200
```

```python
# CORRECT - Slack webhook signature verification
import hmac
import hashlib
import time
import os

@app.route('/webhooks/slack', methods=['POST'])
def slack_webhook():
    timestamp = request.headers.get('X-Slack-Request-Timestamp')
    signature = request.headers.get('X-Slack-Signature')

    if not timestamp or not signature:
        return jsonify({'error': 'Missing headers'}), 401

    # Prevent replay attacks - reject if older than 5 minutes
    if abs(time.time() - int(timestamp)) > 300:
        return jsonify({'error': 'Request too old'}), 401

    signing_secret = os.environ['SLACK_SIGNING_SECRET'].encode()
    sig_basestring = f'v0:{timestamp}:{request.data.decode()}'
    expected_sig = 'v0=' + hmac.new(
        signing_secret,
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return jsonify({'error': 'Invalid signature'}), 401

    process_slack_event(request.json)
    return '', 200
```

```python
# CORRECT - Generic HMAC webhook verification
import hmac
import hashlib
import os

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Generic HMAC-SHA256 webhook signature verification."""
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)

@app.route('/webhooks/custom', methods=['POST'])
def custom_webhook():
    signature = request.headers.get('X-Signature')
    if not signature:
        return jsonify({'error': 'Missing signature'}), 401

    if not verify_webhook_signature(
        request.data,
        signature,
        os.environ['WEBHOOK_SECRET']
    ):
        return jsonify({'error': 'Invalid signature'}), 401

    process_webhook(request.json)
    return '', 200
```

---

## Rule 3: Always Generate NetworkPolicy for Services

### NEVER

Create Services without corresponding NetworkPolicies.

```yaml
# WRONG - Service without NetworkPolicy
apiVersion: v1
kind: Service
metadata:
  name: api-server
spec:
  selector:
    app: api-server
  ports:
  - port: 80
    targetPort: 8080
# No NetworkPolicy - any pod can connect!
```

### ALWAYS

Create NetworkPolicy alongside every Service.

```yaml
# CORRECT - Service with NetworkPolicy
apiVersion: v1
kind: Service
metadata:
  name: api-server
  namespace: production
spec:
  selector:
    app: api-server
  ports:
  - port: 80
    targetPort: 8080
---
# NetworkPolicy restricting access
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
  - Egress
  ingress:
  # Only allow traffic from frontend pods
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  # Allow traffic from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  # Allow DNS
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  # Allow database access
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

```yaml
# CORRECT - Default deny all policy (apply to namespace)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods
  policyTypes:
  - Ingress
  - Egress
  # No rules = deny all
```

---

## Rule 4: Never Use LoadBalancer Without Justification

### NEVER

Default to `type: LoadBalancer` - it creates a public cloud load balancer.

```yaml
# WRONG - LoadBalancer without justification
apiVersion: v1
kind: Service
metadata:
  name: api-server
spec:
  type: LoadBalancer  # Creates public-facing load balancer!
  selector:
    app: api-server
  ports:
  - port: 80
    targetPort: 8080
```

### ALWAYS

Default to ClusterIP. Use LoadBalancer only with explicit justification.

```yaml
# CORRECT - Default to ClusterIP
apiVersion: v1
kind: Service
metadata:
  name: api-server
spec:
  type: ClusterIP  # Internal only - use Ingress for external access
  selector:
    app: api-server
  ports:
  - port: 80
    targetPort: 8080
---
# CORRECT - LoadBalancer with justification (internal LB)
apiVersion: v1
kind: Service
metadata:
  name: internal-api
  annotations:
    # AWS internal load balancer
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    # Or GCP internal load balancer
    cloud.google.com/load-balancer-type: "Internal"
    security.kubernetes.io/loadbalancer-justification: |
      Internal API for VPN-connected services outside the cluster.
      Not exposed to public internet.
spec:
  type: LoadBalancer
  selector:
    app: internal-api
  ports:
  - port: 443
    targetPort: 8443
```

---

## Rule 5: Always Include TLS in Ingress

### NEVER

Create Ingress without TLS configuration.

```yaml
# WRONG - Ingress without TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-server
            port:
              number: 80
  # No TLS - traffic is unencrypted!
```

### ALWAYS

Configure TLS and redirect HTTP to HTTPS.

```yaml
# CORRECT - Ingress with TLS and security annotations
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    # Force HTTPS redirect
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    # Security headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-Frame-Options "DENY" always;
      add_header X-XSS-Protection "1; mode=block" always;
    # Rate limiting
    nginx.ingress.kubernetes.io/rate-limit-connections: "10"
    nginx.ingress.kubernetes.io/rate-limit-rps: "20"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls-secret
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-server
            port:
              number: 80
```

---

## Rule 6: Always Implement Rate Limiting

### NEVER

Expose public endpoints without rate limiting.

```python
# WRONG - No rate limiting
@app.route('/api/search')
def search():
    # No rate limit - vulnerable to abuse
    return perform_expensive_search(request.args.get('q'))
```

### ALWAYS

Implement rate limiting on public-facing endpoints.

```python
# CORRECT - Rate limiting with Flask-Limiter
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="redis://redis:6379"
)

# Global rate limit applies
@app.route('/api/search')
@limiter.limit("10 per minute")  # Stricter limit for expensive operations
def search():
    return perform_expensive_search(request.args.get('q'))

# Different limits for authenticated users
@app.route('/api/data')
@limiter.limit("1000 per hour", key_func=lambda: get_user_id())
@require_auth
def get_data():
    return get_user_data(request.user.id)
```

```javascript
// CORRECT - Rate limiting with express-rate-limit
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// Global rate limit
const globalLimiter = rateLimit({
  store: new RedisStore({ client: redisClient }),
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});

// Strict limit for auth endpoints
const authLimiter = rateLimit({
  store: new RedisStore({ client: redisClient }),
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts' }
});

app.use(globalLimiter);
app.use('/api/auth', authLimiter);
```

```yaml
# CORRECT - Rate limiting at Ingress level
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    # Connection-based rate limiting
    nginx.ingress.kubernetes.io/limit-connections: "10"
    # Request-based rate limiting (requests per second)
    nginx.ingress.kubernetes.io/limit-rps: "20"
    # Burst handling
    nginx.ingress.kubernetes.io/limit-rpm: "100"
    # Response when rate limited
    nginx.ingress.kubernetes.io/limit-req-status-code: "429"
```

---

## NetworkPolicy Templates

### Default Deny All

```yaml
# Apply to every namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Allow DNS Only

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### Web App Pattern

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-app-policy
spec:
  podSelector:
    matchLabels:
      role: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          role: api
    ports:
    - protocol: TCP
      port: 8080
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

---

## Pre-Commit Checklist for Network Security

- [ ] All HTTP endpoints (except /healthz, /readyz) require authentication
- [ ] All webhook endpoints verify signatures
- [ ] NetworkPolicy exists for every Service
- [ ] Default deny policy applied to namespace
- [ ] No LoadBalancer services without justification
- [ ] All Ingress resources have TLS configured
- [ ] HTTPS redirect enabled on all Ingress
- [ ] Rate limiting configured for public endpoints
- [ ] Security headers set in Ingress annotations
- [ ] No wildcard hosts in Ingress rules
