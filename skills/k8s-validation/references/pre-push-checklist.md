# Pre-Push Security Checklist

> Version: 1.0 | Last Updated: 2026-03-03
>
> Copy this checklist into your PR template to ensure security compliance.

---

## Instructions

Before pushing code that includes Kubernetes manifests, Dockerfiles, Helm charts, or application code that handles secrets, authentication, or runs in Kubernetes, verify all applicable items below.

Mark items as:
- `[x]` - Verified and compliant
- `[N/A]` - Not applicable to this change
- `[ ]` - Not yet verified (must be resolved before merge)

---

## 1. Secrets Management

- [ ] No hardcoded secrets in source code (API keys, passwords, tokens)
- [ ] No secrets in ConfigMaps (use Secrets or external secret managers)
- [ ] All secrets use `secretKeyRef` or volume mounts in manifests
- [ ] Application fails fast on missing required secrets
- [ ] No secrets in log output at any level
- [ ] No secrets in error messages or HTTP responses
- [ ] TLS certificates mounted as files (not env vars)
- [ ] Secret manifests use placeholders (not real values)
- [ ] `.gitignore` includes `*.pem`, `*.key`, `secrets.yaml`, `.env*`

---

## 2. Pod & Container Security

- [ ] SecurityContext defined at pod and container level
- [ ] `runAsNonRoot: true`
- [ ] `readOnlyRootFilesystem: true`
- [ ] `allowPrivilegeEscalation: false`
- [ ] `capabilities.drop: [ALL]`
- [ ] `privileged: false` (or documented justification)
- [ ] `automountServiceAccountToken: false` (or documented justification)
- [ ] Resource requests AND limits defined (CPU and memory)
- [ ] Liveness and readiness probes configured
- [ ] `seccompProfile.type: RuntimeDefault`
- [ ] No hostPath volumes (or documented justification)
- [ ] No hostNetwork/hostPID/hostIPC (or documented justification)

---

## 3. Network Exposure & Ingress

- [ ] All HTTP endpoints require authentication (except /healthz, /readyz)
- [ ] Webhook endpoints verify signatures (Stripe, GitHub, Slack, etc.)
- [ ] NetworkPolicy exists for every Service
- [ ] Default deny policy applied to namespace
- [ ] No LoadBalancer services without documented justification
- [ ] All Ingress resources have TLS configured
- [ ] HTTPS redirect enabled on all Ingress
- [ ] Rate limiting configured for public endpoints
- [ ] Security headers set in Ingress annotations
- [ ] No wildcard hosts in Ingress rules

---

## 4. Supply Chain Security

- [ ] All dependencies pinned to exact versions (no ^, ~, or ranges)
- [ ] Lock files committed (package-lock.json, go.sum, Cargo.lock)
- [ ] Dependency hashes verified where supported
- [ ] Base images pinned by digest (sha256)
- [ ] No `:latest` or unpinned image tags
- [ ] No `curl | bash` patterns in Dockerfile
- [ ] Multi-stage build used
- [ ] Final image runs as non-root user
- [ ] `.dockerignore` excludes secrets, tests, docs
- [ ] No build tools in production image
- [ ] Minimal base image used (slim, alpine, or distroless)

---

## 5. Internal Service Authentication

- [ ] No endpoints trust "internal" status alone
- [ ] All service-to-service calls use authentication
- [ ] Tokens cryptographically verified (not just checked for presence)
- [ ] mTLS enabled if using service mesh
- [ ] Only /healthz and /readyz are unauthenticated
- [ ] Each service has dedicated ServiceAccount
- [ ] Service identity verified in authentication
- [ ] Short-lived tokens used (< 1 hour expiry)

---

## 6. File Handling & Path Security

- [ ] All user-supplied filenames sanitized
- [ ] Path traversal prevention implemented (resolve + prefix check)
- [ ] File types validated by magic bytes (not just extension)
- [ ] File size limits enforced before reading full content
- [ ] Uploaded files saved with generated names (not user names)
- [ ] Temp files use secure creation (tempfile module)
- [ ] Temp files cleaned up in finally blocks
- [ ] Secrets not accessible via file download APIs

---

## 7. LLM & AI Workload Security

- [ ] User input never directly concatenated into system prompts (LLM01)
- [ ] Output filtering for PII, credentials, internal URLs (LLM02)
- [ ] Per-user rate limiting implemented (LLM10)
- [ ] Input length limits enforced (LLM10)
- [ ] Request timeouts configured (LLM10)
- [ ] Tool permissions follow least-privilege (LLM06)
- [ ] Write operations require human confirmation (LLM06)
- [ ] No secrets in system prompts (LLM07)
- [ ] No internal URLs or infrastructure details in prompts (LLM07)

---

## 8. Helm & Manifest Generation

- [ ] No hardcoded secrets in values.yaml
- [ ] Secret templates use references, not values
- [ ] PodDisruptionBudget included for production
- [ ] Standard Kubernetes labels applied
- [ ] Liveness and readiness probes configured
- [ ] SecurityContext with secure defaults
- [ ] Resource requests and limits defined
- [ ] Dedicated ServiceAccount created
- [ ] NetworkPolicy template included
- [ ] Ingress includes TLS configuration

---

## 9. RBAC & Service Accounts

- [ ] Each workload has dedicated ServiceAccount
- [ ] No wildcard (*) verbs without documented justification
- [ ] No wildcard (*) resources without documented justification
- [ ] Role used instead of ClusterRole where possible
- [ ] Secrets access only when explicitly required
- [ ] `resourceNames` used where possible
- [ ] RBAC includes documentation annotations
- [ ] No default service account used by application pods

---

## 10. Observability & Incident Response

- [ ] Structured logging implemented (JSON format)
- [ ] No secrets logged
- [ ] No PII logged
- [ ] Prometheus metrics endpoint exposed
- [ ] Standard metrics implemented (requests, latency, errors)
- [ ] Error rate alerts configured
- [ ] Security event alerts configured
- [ ] Authentication events audit logged
- [ ] Admin actions audit logged

---

## Quick Reference: Critical Violations

The following are **NEVER** acceptable without explicit security review:

| Category | Violation |
|----------|-----------|
| Secrets | Hardcoded secrets in any file |
| Secrets | Secrets in error messages or logs |
| Container | `privileged: true` |
| Container | Running as root without justification |
| Container | `:latest` image tag |
| Supply Chain | `curl \| bash` in Dockerfile |
| RBAC | Wildcard (*) verbs or resources |
| RBAC | ClusterRole for namespace-scoped access |
| Network | LoadBalancer without justification |
| Network | Ingress without TLS |
| Auth | Unauthenticated endpoints (except health) |
| LLM | Secrets in system prompts |
| LLM | Raw user input in prompts |

---

## Sign-Off

- [ ] I have reviewed all applicable sections above
- [ ] All critical violations have been addressed or have documented exceptions
- [ ] Security-sensitive changes have been reviewed by a second team member

**Reviewer**: ___________________
**Date**: ___________________
