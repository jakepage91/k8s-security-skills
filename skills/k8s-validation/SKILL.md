---
name: k8s-validation
description: Validate Kubernetes manifests, Dockerfiles, Helm charts, and application code for security best practices, code logic errors, and data-flow correctness. Automatically applies NEVER/ALWAYS guardrails across 11 validation domains.
metadata:
  author: MetalBear
  version: "2.0"
  last_updated: "2026-03-05"
---

# Kubernetes Validation Skill

## Purpose

Act as a persistent guardrail for AI code generation in Kubernetes environments — covering both security and code correctness. This skill enforces concrete, actionable rules across security, logic correctness, and data-flow integrity whenever you generate or modify:

- Kubernetes manifests (Deployments, Services, Ingress, ConfigMaps, Secrets, etc.)
- Dockerfiles and container configurations
- Helm charts and Kustomize overlays
- Application code that runs in Kubernetes
- CI/CD pipelines for Kubernetes deployments
- LLM/AI workloads in Kubernetes

## Critical First Steps

**Before generating ANY Kubernetes-related code, load the relevant reference files:**

```
references/secrets-management.md        - For secrets, credentials, API keys
references/pod-container-security.md    - For Deployments, Pods, SecurityContext
references/network-exposure.md          - For Services, Ingress, NetworkPolicies
references/supply-chain-security.md     - For Dockerfiles, dependencies
references/internal-service-auth.md     - For service-to-service communication
references/file-handling-security.md    - For file uploads, path operations
references/llm-ai-security.md           - For LLM/AI workloads (OWASP LLM Top 10)
references/helm-manifest-security.md    - For Helm charts, raw manifests
references/rbac-service-accounts.md     - For RBAC, ServiceAccounts
references/observability-incident-response.md - For logging, metrics, alerting
references/code-logic.md                - For code correctness, data-flow bugs, HTTP/SQL mismatches
references/pre-push-checklist.md        - Final verification before commit
```

## Core Principles

### NEVER Rules (Hard Requirements)

These rules MUST NOT be violated under any circumstances:

1. **NEVER** hardcode secrets in source code, manifests, or Dockerfiles
2. **NEVER** use `privileged: true` without explicit user justification
3. **NEVER** use `:latest` or unpinned image tags
4. **NEVER** use `curl | bash` install patterns in Dockerfiles
5. **NEVER** skip authentication on HTTP endpoints (except /healthz, /readyz)
6. **NEVER** use ClusterRole when a namespaced Role suffices
7. **NEVER** use wildcard (*) verbs/resources in RBAC without justification
8. **NEVER** log secret values, credentials, or PII
9. **NEVER** use user input directly in file paths without sanitization
10. **NEVER** include secrets or internal URLs in LLM system prompts

### ALWAYS Rules (Hard Requirements)

These rules MUST be followed in all generated code:

1. **ALWAYS** use Kubernetes Secrets or external secret managers for credentials
2. **ALWAYS** set SecurityContext with runAsNonRoot, readOnlyRootFilesystem
3. **ALWAYS** set resource requests AND limits (CPU and memory)
4. **ALWAYS** set `automountServiceAccountToken: false` unless K8s API access needed
5. **ALWAYS** pin dependencies to exact versions (no ^, ~, or ranges)
6. **ALWAYS** use multi-stage Docker builds
7. **ALWAYS** generate NetworkPolicy when creating a Service
8. **ALWAYS** include TLS configuration in Ingress resources
9. **ALWAYS** create dedicated ServiceAccount per workload
10. **ALWAYS** include liveness and readiness probes

## Workflow

### When Generating New Resources

1. **Identify the resource type** and load relevant reference files
2. **Apply all applicable NEVER/ALWAYS rules** from loaded references
3. **Write the manifest file to disk** using the appropriate path (e.g. `k8s/<resource-name>.yaml`, or alongside existing manifests if the project already has a manifest directory). Write clean YAML — do not clutter it with security comment blocks.
4. **Update `SECURITY-POSTURE.md`** in the project root (create it if it does not exist). Add an entry for each file written, recording which security controls were applied and why. Use the format defined in the Response Format section below.
5. **Ensure `SECURITY-POSTURE.md` is in `.gitignore`** — append the entry if it is not already present, creating `.gitignore` if it does not exist.
6. **Confirm what was written** and provide the user with any additional steps needed (e.g., "create the Secret separately with: kubectl create secret...")

### When Reviewing Existing Code

1. **Load relevant reference files** based on resource types present
2. **Scan for NEVER rule violations** - these are critical findings
3. **Check for missing ALWAYS requirements** - these are high-priority findings
4. **Update `SECURITY-POSTURE.md`** with a findings section for the reviewed files, listing each violation with its severity, location, and remediation
5. **Ensure `SECURITY-POSTURE.md` is in `.gitignore`** — append the entry if it is not already present, creating `.gitignore` if it does not exist.
6. **Offer to fix** identified issues directly

### Response Format

Generated manifest files should be clean YAML with no security comment blocks. All security reasoning is recorded in `SECURITY-POSTURE.md` instead, using this structure:

```markdown
## `k8s/<resource-name>.yaml` — <Kind> (<date>)

**Controls applied:**
- `readOnlyRootFilesystem: true` + `emptyDir` at `/tmp` — file upload feature requires writable temp dir; root FS locked down per pod-container-security Rule 5
- `automountServiceAccountToken: false` — no K8s API access required
- `NetworkPolicy` — restricts ingress to llm-gateway namespace only
- `runAsNonRoot: true`, `runAsUser: 1000` — non-root execution enforced
- Resource limits set: 256Mi–512Mi memory, 250m–500m CPU

**Additional steps required:**
- Create the API key Secret separately: `kubectl create secret generic ...`
```

When identifying security issues during a review, append a findings section:

```markdown
## Security Review: `<file>` (<date>)

> This audit is read-only. No files were modified.

### CRITICAL: [Issue Title]
- **Rule**: NEVER/ALWAYS reference
- **Risk**: What could happen if not addressed
- **Recommended fix**: Exact remediation with a corrected YAML/code snippet, ready to apply when the team is ready to deploy the change
```

## Quick Reference: Security Controls by Resource Type

| Resource Type | Required Security Controls |
|--------------|---------------------------|
| Deployment/Pod | SecurityContext, resources, serviceAccount, probes |
| Service | NetworkPolicy, no LoadBalancer without justification |
| Ingress | TLS, authentication annotation |
| Secret | Never in git, use secretKeyRef |
| ConfigMap | No secrets, validate content |
| ServiceAccount | Dedicated per workload, minimal RBAC |
| Role/ClusterRole | Least privilege, no wildcards |
| Dockerfile | Multi-stage, pinned images, no curl\|bash |
| Helm Chart | Templated secrets, PDB, probes |

## Integration with Pre-Push Checklist

Before any code is committed, verify against `references/pre-push-checklist.md`. This checklist covers all critical items from every security domain and can be copied directly into PR templates.

## Example Interactions

**User:** "Create a deployment for my Node.js API"

**Response:** Load `pod-container-security.md` and `secrets-management.md`, then generate:
- Deployment with full SecurityContext
- Dedicated ServiceAccount with `automountServiceAccountToken: false`
- Resource requests and limits
- Liveness and readiness probes
- Environment variables using secretKeyRef for any credentials
- Note about creating NetworkPolicy separately

**User:** "Add Stripe webhook handling to my app"

**Response:** Load `network-exposure.md` and `secrets-management.md`, then generate:
- Webhook endpoint with signature verification
- Secret for webhook signing key using K8s Secret
- Rate limiting middleware
- Structured logging (without logging payload contents)

**User:** "Review this Dockerfile for security issues"

**Response:** Load `supply-chain-security.md`, scan for:
- Unpinned base images → require digest pinning
- `curl | bash` patterns → require explicit package installs
- Running as root → require USER directive
- Build tools in final image → require multi-stage build
- Unpinned dependencies → require exact versions
