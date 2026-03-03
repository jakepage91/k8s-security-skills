# Observability & Incident Response Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for secure observability practices including structured logging, metrics exposure, alerting, and audit logging for security-sensitive operations.

---

## Rule 1: Always Use Structured Logging

### NEVER

Use unstructured log formats or print statements in production.

```python
# WRONG - Unstructured logging
print(f"User {user_id} logged in")
print(f"Error processing request: {error}")
logging.info(f"Processing order {order_id} for user {user_id}")
```

```javascript
// WRONG - Console.log in production
console.log('User logged in:', userId);
console.log('Error:', error.message, error.stack);
```

### ALWAYS

Use structured logging with consistent fields.

```python
# CORRECT - Structured logging with Python
import structlog
import logging

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# CORRECT - Structured log entries
logger.info("user_login",
    user_id=user_id,
    ip_address=request.remote_addr,
    user_agent=request.headers.get('User-Agent'),
    auth_method="oauth2"
)

logger.error("request_failed",
    request_id=request_id,
    path=request.path,
    method=request.method,
    status_code=500,
    error_type=type(error).__name__,
    # Note: NOT logging error.message if it might contain secrets
)
```

```javascript
// CORRECT - Structured logging with pino (Node.js)
const pino = require('pino');

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['password', 'token', 'apiKey', 'secret', 'authorization'],
    censor: '[REDACTED]'
  }
});

// CORRECT - Structured log entries
logger.info({
  event: 'user_login',
  userId,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  authMethod: 'oauth2'
});

logger.error({
  event: 'request_failed',
  requestId,
  path: req.path,
  method: req.method,
  statusCode: 500,
  errorType: error.name
  // NOT logging error.message
});
```

---

## Rule 2: Never Log Secrets or PII

### NEVER

Log sensitive information including passwords, tokens, API keys, or PII.

```python
# WRONG - Logging secrets
logger.info(f"Connecting with password: {db_password}")
logger.debug(f"API key: {api_key}")
logger.info(f"User token: {jwt_token}")

# WRONG - Logging PII
logger.info(f"Processing user: {email}, SSN: {ssn}")
logger.info(f"Credit card: {card_number}")

# WRONG - Logging request/response bodies that may contain secrets
logger.debug(f"Request body: {request.json}")
logger.debug(f"Response: {response.text}")
```

### ALWAYS

Redact sensitive fields and use allowlists for logged data.

```python
# CORRECT - Automatic redaction
import structlog
import re

SENSITIVE_PATTERNS = [
    (r'password["\']?\s*[:=]\s*["\']?[^"\'}\s]+', 'password=[REDACTED]'),
    (r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\'}\s]+', 'api_key=[REDACTED]'),
    (r'token["\']?\s*[:=]\s*["\']?[^"\'}\s]+', 'token=[REDACTED]'),
    (r'bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 'bearer [REDACTED]'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b', '[CARD]'),
]

def redact_sensitive(_, __, event_dict):
    """Redact sensitive information from log entries."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            for pattern, replacement in SENSITIVE_PATTERNS:
                value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
            event_dict[key] = value
    return event_dict

structlog.configure(
    processors=[
        redact_sensitive,  # Add redaction processor
        structlog.processors.JSONRenderer()
    ]
)

# CORRECT - Safe logging practices
logger.info("authentication_attempt",
    user_id=user_id,
    success=True,
    ip_address=request.remote_addr,
    # NOT logging: password, token, session data
)

# CORRECT - Allowlist approach for request logging
SAFE_REQUEST_FIELDS = ['method', 'path', 'content_type', 'content_length']

def get_safe_request_info(request):
    return {k: getattr(request, k, None) for k in SAFE_REQUEST_FIELDS}

logger.info("request_received", **get_safe_request_info(request))
```

```python
# CORRECT - Logging class with built-in protection
class SecureLogger:
    REDACT_FIELDS = {
        'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
        'authorization', 'auth', 'credential', 'private_key', 'ssn',
        'credit_card', 'card_number', 'cvv', 'pin'
    }

    def __init__(self, logger):
        self.logger = logger

    def _sanitize(self, data: dict) -> dict:
        """Recursively sanitize sensitive fields."""
        sanitized = {}
        for key, value in data.items():
            if key.lower() in self.REDACT_FIELDS:
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize(value)
            elif isinstance(value, str) and len(value) > 100:
                # Truncate long strings that might contain sensitive data
                sanitized[key] = value[:100] + '...[TRUNCATED]'
            else:
                sanitized[key] = value
        return sanitized

    def info(self, event: str, **kwargs):
        self.logger.info(event, **self._sanitize(kwargs))

    def error(self, event: str, **kwargs):
        self.logger.error(event, **self._sanitize(kwargs))
```

---

## Rule 3: Always Expose Prometheus Metrics for Services

### NEVER

Deploy services without metrics endpoints.

```python
# WRONG - No metrics
@app.route('/api/data')
def get_data():
    return jsonify(fetch_data())
# No visibility into request rates, latencies, errors
```

### ALWAYS

Expose Prometheus metrics with standard naming conventions.

```python
# CORRECT - Prometheus metrics with python prometheus_client
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from flask import Flask, Response
import time

app = Flask(__name__)

# Define metrics with consistent naming
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint'],
    buckets=[.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10]
)

IN_PROGRESS = Gauge(
    'http_requests_in_progress',
    'HTTP requests currently in progress',
    ['method', 'endpoint']
)

# Error metrics
ERROR_COUNT = Counter(
    'app_errors_total',
    'Total application errors',
    ['error_type', 'endpoint']
)

# Business metrics
ORDERS_PROCESSED = Counter(
    'orders_processed_total',
    'Total orders processed',
    ['status']
)

def track_request(f):
    """Decorator to track request metrics."""
    @wraps(f)
    def decorated(*args, **kwargs):
        endpoint = request.endpoint or 'unknown'
        method = request.method

        IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()
        start_time = time.time()

        try:
            response = f(*args, **kwargs)
            status = response.status_code if hasattr(response, 'status_code') else 200
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
            return response
        except Exception as e:
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=500).inc()
            ERROR_COUNT.labels(error_type=type(e).__name__, endpoint=endpoint).inc()
            raise
        finally:
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(
                time.time() - start_time
            )
            IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()

    return decorated

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint."""
    return Response(generate_latest(), mimetype='text/plain')

@app.route('/api/data')
@track_request
def get_data():
    return jsonify(fetch_data())
```

```yaml
# CORRECT - Kubernetes manifests for metrics scraping
apiVersion: v1
kind: Service
metadata:
  name: api-server
  labels:
    app: api-server
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
    prometheus.io/path: "/metrics"
spec:
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: metrics
      port: 9090
      targetPort: 9090
  selector:
    app: api-server
---
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-server
  labels:
    app: api-server
spec:
  selector:
    matchLabels:
      app: api-server
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

---

## Rule 4: Always Configure Appropriate Alerting

### ALWAYS

Define alerts for critical conditions with actionable thresholds.

```yaml
# CORRECT - PrometheusRule for alerting
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api-server-alerts
  labels:
    app: api-server
spec:
  groups:
    - name: api-server.rules
      rules:
        # High error rate
        - alert: HighErrorRate
          expr: |
            sum(rate(http_requests_total{status=~"5.."}[5m]))
            /
            sum(rate(http_requests_total[5m])) > 0.05
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "High error rate on {{ $labels.service }}"
            description: "Error rate is {{ $value | humanizePercentage }} over the last 5 minutes"

        # High latency
        - alert: HighLatency
          expr: |
            histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, endpoint))
            > 1
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High latency on {{ $labels.endpoint }}"
            description: "95th percentile latency is {{ $value | humanizeDuration }}"

        # Pod restarts
        - alert: HighPodRestarts
          expr: |
            increase(kube_pod_container_status_restarts_total{namespace="production"}[1h]) > 5
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Pod {{ $labels.pod }} restarting frequently"
            description: "{{ $value }} restarts in the last hour"

        # Memory pressure
        - alert: HighMemoryUsage
          expr: |
            container_memory_usage_bytes{namespace="production"}
            /
            container_spec_memory_limit_bytes{namespace="production"} > 0.9
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High memory usage on {{ $labels.pod }}"
            description: "Memory usage is {{ $value | humanizePercentage }}"

        # Security: Authentication failures
        - alert: HighAuthFailures
          expr: |
            sum(rate(auth_failures_total[5m])) > 10
          for: 5m
          labels:
            severity: critical
            category: security
          annotations:
            summary: "High rate of authentication failures"
            description: "{{ $value }} auth failures per second"

        # Security: Privilege escalation attempts
        - alert: PrivilegeEscalationAttempt
          expr: |
            sum(rate(security_privilege_escalation_attempts_total[5m])) > 0
          for: 1m
          labels:
            severity: critical
            category: security
          annotations:
            summary: "Privilege escalation attempt detected"
            description: "{{ $value }} attempts detected"
```

---

## Rule 5: Always Implement Audit Logging for Security Events

### ALWAYS

Log security-sensitive operations with sufficient detail for forensics.

```python
# CORRECT - Security audit logging
from datetime import datetime
import hashlib
import json

class SecurityAuditLogger:
    """Audit logger for security-sensitive operations."""

    def __init__(self, logger):
        self.logger = logger

    def _get_request_context(self, request) -> dict:
        """Extract request context for audit trail."""
        return {
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:200],
            'request_id': request.headers.get('X-Request-ID', ''),
            'forwarded_for': request.headers.get('X-Forwarded-For', ''),
        }

    def log_authentication(self, request, user_id: str, success: bool,
                          method: str, failure_reason: str = None):
        """Log authentication attempts."""
        self.logger.info("security_audit",
            event_type="authentication",
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            success=success,
            auth_method=method,
            failure_reason=failure_reason if not success else None,
            **self._get_request_context(request)
        )

    def log_authorization(self, request, user_id: str, resource: str,
                         action: str, allowed: bool):
        """Log authorization decisions."""
        self.logger.info("security_audit",
            event_type="authorization",
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            resource=resource,
            action=action,
            allowed=allowed,
            **self._get_request_context(request)
        )

    def log_data_access(self, request, user_id: str, resource_type: str,
                       resource_id: str, action: str):
        """Log access to sensitive data."""
        self.logger.info("security_audit",
            event_type="data_access",
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            resource_type=resource_type,
            resource_id=self._hash_id(resource_id),  # Hash for privacy
            action=action,
            **self._get_request_context(request)
        )

    def log_admin_action(self, request, admin_id: str, action: str,
                        target: str, details: dict):
        """Log administrative actions."""
        self.logger.warning("security_audit",
            event_type="admin_action",
            timestamp=datetime.utcnow().isoformat(),
            admin_id=admin_id,
            action=action,
            target=target,
            details=self._sanitize_details(details),
            **self._get_request_context(request)
        )

    def log_security_event(self, request, event_name: str, severity: str,
                          details: dict):
        """Log security events (potential attacks, anomalies)."""
        log_method = self.logger.critical if severity == 'critical' else self.logger.warning
        log_method("security_audit",
            event_type="security_event",
            event_name=event_name,
            severity=severity,
            timestamp=datetime.utcnow().isoformat(),
            details=self._sanitize_details(details),
            **self._get_request_context(request)
        )

    def _hash_id(self, resource_id: str) -> str:
        """Hash resource IDs for privacy in logs."""
        return hashlib.sha256(resource_id.encode()).hexdigest()[:16]

    def _sanitize_details(self, details: dict) -> dict:
        """Remove sensitive fields from details."""
        sensitive_keys = {'password', 'token', 'secret', 'key', 'credential'}
        return {k: '[REDACTED]' if k.lower() in sensitive_keys else v
                for k, v in details.items()}


# Usage
audit = SecurityAuditLogger(logger)

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = authenticate(username, password)

    if user:
        audit.log_authentication(request, user.id, success=True, method='password')
        return create_session(user)
    else:
        audit.log_authentication(request, username, success=False,
                                method='password', failure_reason='invalid_credentials')
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/admin/users/<user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    audit.log_admin_action(request, g.admin.id, 'delete_user',
                          target=user_id, details={'reason': request.json.get('reason')})
    perform_delete(user_id)
    return '', 204
```

---

## Rule 6: Configure Kubernetes Audit Logging

### ALWAYS

Enable and configure Kubernetes audit logging for security events.

```yaml
# CORRECT - Kubernetes audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Don't log read-only requests to certain endpoints
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
      - group: ""
        resources: ["endpoints", "services", "services/status"]

  # Don't log health checks
  - level: None
    nonResourceURLs:
      - /healthz*
      - /readyz*
      - /livez*

  # Log authentication at Metadata level
  - level: Metadata
    resources:
      - group: "authentication.k8s.io"
        resources: ["tokenreviews"]

  # Log all changes to secrets at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
    verbs: ["create", "update", "patch", "delete"]

  # Log RBAC changes at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Log pod exec/attach at RequestResponse level (potential security event)
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Log all other write operations at Metadata level
  - level: Metadata
    verbs: ["create", "update", "patch", "delete"]

  # Log everything else at Metadata level
  - level: Metadata
```

---

## Pre-Commit Checklist for Observability

### Logging
- [ ] Structured logging implemented (JSON format)
- [ ] No secrets logged (passwords, tokens, API keys)
- [ ] No PII logged (emails, SSNs, credit cards)
- [ ] Automatic redaction configured
- [ ] Log levels appropriate (info for normal, warning for issues, error for failures)
- [ ] Request IDs included for correlation

### Metrics
- [ ] Prometheus metrics endpoint exposed
- [ ] Standard metrics implemented (requests, latency, errors)
- [ ] Business metrics defined
- [ ] ServiceMonitor/annotations for discovery
- [ ] Metrics endpoint protected or restricted via NetworkPolicy

### Alerting
- [ ] Error rate alerts configured
- [ ] Latency alerts configured
- [ ] Resource usage alerts configured
- [ ] Security event alerts configured
- [ ] Alert severity levels appropriate
- [ ] Runbooks linked in alert annotations

### Audit Logging
- [ ] Authentication events logged
- [ ] Authorization decisions logged
- [ ] Admin actions logged
- [ ] Security events logged
- [ ] Kubernetes audit policy configured
- [ ] Audit logs shipped to secure storage
