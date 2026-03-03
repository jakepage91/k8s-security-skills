# Kubernetes Security Skill

Comprehensive security guardrails for AI code generation in Kubernetes environments.

## What This Skill Does

When activated, this skill automatically enforces security best practices across:

- **Secrets Management**: Never hardcode, always use K8s Secrets or external managers
- **Pod Security**: SecurityContext hardening, resource limits, non-root execution
- **Network Security**: NetworkPolicies, TLS, authentication requirements
- **Supply Chain**: Pinned dependencies, digest-pinned images, secure Dockerfiles
- **Service Auth**: mTLS, JWT validation, no "internal = safe" assumptions
- **File Security**: Path traversal prevention, input sanitization
- **LLM Security**: OWASP LLM Top 10 compliance
- **Helm/Manifests**: Secure templating, PDBs, probes
- **RBAC**: Least privilege, dedicated service accounts
- **Observability**: Secure logging, metrics exposure

## Reference Files

Detailed rules with code examples are in the `references/` directory:

| File | Coverage |
|------|----------|
| `secrets-management.md` | API keys, DB credentials, TLS certs, OAuth tokens |
| `pod-container-security.md` | SecurityContext, resources, Pod Security Standards |
| `network-exposure.md` | Services, Ingress, NetworkPolicies, webhooks |
| `supply-chain-security.md` | Dockerfiles, pip/npm/go dependencies |
| `internal-service-auth.md` | Service-to-service auth, mTLS |
| `file-handling-security.md` | Path traversal, file uploads |
| `llm-ai-security.md` | OWASP LLM Top 10 mapped rules |
| `helm-manifest-security.md` | Helm charts, raw manifests |
| `rbac-service-accounts.md` | Roles, ClusterRoles, ServiceAccounts |
| `observability-incident-response.md` | Logging, metrics, alerting |
| `pre-push-checklist.md` | PR template checklist |

## Usage

The skill activates automatically when generating Kubernetes-related code. All NEVER/ALWAYS rules are enforced by default.
