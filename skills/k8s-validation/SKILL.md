---
name: k8s-validation
description: Validate Kubernetes manifests, Dockerfiles, Helm charts, and application code for both security and correctness. Enforces NEVER/ALWAYS rules across security domains and correctness domains so AI-generated code is shaped to fit a real Kubernetes environment.
metadata:
  author: MetalBear
  version: "3.0"
  last_updated: "2026-04-07"
---

# Kubernetes Validation Skill

## Purpose

Act as a persistent guardrail for AI code generation in Kubernetes environments. Validation here covers two equal halves:

- **Security**: secrets, pod hardening, network exposure, supply chain, RBAC, file handling, LLM workloads, Helm/manifests, internal service auth, observability, app security.
- **Correctness**: HTTP method/parameter handling, data flow through queries, API contracts and response shapes, async/error handling, environment configuration wiring, and test coverage for new code.

The skill enforces concrete NEVER/ALWAYS rules whenever you generate or modify:

- Kubernetes manifests (Deployments, Services, Ingress, ConfigMaps, Secrets, etc.)
- Dockerfiles and container configurations
- Helm charts and Kustomize overlays
- Application code that runs in Kubernetes
- CI/CD pipelines for Kubernetes deployments
- LLM/AI workloads in Kubernetes

## Critical First Steps

**Before generating ANY Kubernetes-related code, load the relevant reference files.**

### Security references

```
references/secrets-management.md            - secrets, credentials, API keys
references/pod-container-security.md        - Deployments, Pods, SecurityContext
references/network-exposure.md              - Services, Ingress, NetworkPolicies
references/supply-chain-security.md         - Dockerfiles, dependencies
references/internal-service-auth.md         - service-to-service communication
references/file-handling-security.md        - file uploads, path operations
references/llm-ai-security.md               - LLM/AI workloads (OWASP LLM Top 10)
references/helm-manifest-security.md        - Helm charts, raw manifests
references/rbac-service-accounts.md         - RBAC, ServiceAccounts
references/observability-incident-response.md - logging, metrics, alerting
references/app-security.md                  - app-layer auth, IDOR, injection
```

### Correctness references

```
references/correctness-http-and-types.md         - HTTP method/param sources, type coercion
references/correctness-data-flow.md              - SQL alias mismatches, WHERE clause gaps, end-to-end data flow
references/correctness-api-contracts.md          - response shapes, pagination, backwards compatibility
references/correctness-async-and-errors.md       - missing await, swallowed errors
references/correctness-environment-config.md     - env var name/Secret/Helm wiring mismatches
references/correctness-test-coverage.md          - integration test requirements for new code
```

### Meta

```
references/pre-push-checklist.md   - final verification before commit
```

## Core Principles

### NEVER Rules (hard requirements)

These rules MUST NOT be violated under any circumstances:

#### Security NEVERs

1. **NEVER** hardcode secrets in source code, manifests, or Dockerfiles.
2. **NEVER** use `privileged: true` without explicit user justification.
3. **NEVER** use `:latest` or unpinned image tags.
4. **NEVER** use `curl | bash` install patterns in Dockerfiles.
5. **NEVER** skip authentication on HTTP endpoints (except `/healthz`, `/readyz`).
6. **NEVER** use ClusterRole when a namespaced Role suffices.
7. **NEVER** use wildcard (`*`) verbs/resources in RBAC without justification.
8. **NEVER** log secret values, credentials, or PII.
9. **NEVER** use user input directly in file paths without sanitization.
10. **NEVER** include secrets or internal URLs in LLM system prompts.

#### Correctness NEVERs

1. **NEVER** read parameters from a source that doesn't match the HTTP method (`req.body` in a GET, etc.).
2. **NEVER** build conditional WHERE clauses that silently become no-ops when input is missing.
3. **NEVER** omit `await` on async calls whose result is used synchronously.
4. **NEVER** catch errors and silently continue with default/fallback values that hide the real failure.
5. **NEVER** rename or remove an API response field without versioning the endpoint or updating all consumers.
6. **NEVER** assume an env var name in code matches a Kubernetes Secret key without verifying both sides.

### ALWAYS Rules (hard requirements)

These rules MUST be followed in all generated code:

#### Security ALWAYS

1. **ALWAYS** use Kubernetes Secrets or external secret managers for credentials.
2. **ALWAYS** set SecurityContext with `runAsNonRoot`, `readOnlyRootFilesystem`.
3. **ALWAYS** set resource requests AND limits (CPU and memory).
4. **ALWAYS** set `automountServiceAccountToken: false` unless K8s API access is needed.
5. **ALWAYS** pin dependencies to exact versions (no `^`, `~`, or ranges).
6. **ALWAYS** use multi-stage Docker builds.
7. **ALWAYS** generate a NetworkPolicy when creating a Service.
8. **ALWAYS** include TLS configuration in Ingress resources.
9. **ALWAYS** create a dedicated ServiceAccount per workload.
10. **ALWAYS** include liveness and readiness probes.

#### Correctness ALWAYS

1. **ALWAYS** verify SQL column names or aliases match the property names used in downstream code.
2. **ALWAYS** verify response shapes match what consumers (frontend, other services) destructure.
3. **ALWAYS** validate required configuration at startup and fail fast if anything is missing.
4. **ALWAYS** trace data from input through queries to output to verify the full pipeline is connected.
5. **ALWAYS** generate at least one integration test for any new HTTP handler, message consumer, or background job.
6. **ALWAYS** when adding security or filtering logic, write a test that proves the filter blocks the thing it claims to block.

## Workflow

### When generating new resources

1. **Scan the existing codebase first.** Before generating any code, search for:
   - Existing auth middleware and decorators: grep for `@require_auth`, `@login_required`, `requireAuth`, `authenticate`, `authMiddleware`, `verifyToken`. Use what already exists — do not invent a new auth pattern.
   - Existing sanitization/filtering utilities: grep for `filter_pii`, `sanitize`, `redact`, `scrub`. If one exists, import and use it.
   - Existing error handling patterns: grep for `@app.errorhandler`, `app.use.*err`, `handleError`. Match the project convention.
   - Existing test location and naming convention: check `tests/`, `__tests__/`, `spec/` to understand where integration tests live.
2. Identify the resource type and load the relevant security AND correctness references.
3. Apply all applicable NEVER/ALWAYS rules from loaded references.
4. Write the file to disk at the appropriate path. Write clean code or YAML — do not clutter it with rule comment blocks.
5. Update `SECURITY-POSTURE.md` in the project root (create it if needed). Add an entry recording which controls were applied and why.
6. Ensure `SECURITY-POSTURE.md` is in `.gitignore`.
7. Confirm what was written and provide any additional steps needed (e.g. "create the Secret separately with: `kubectl create secret ...`").

### When reviewing existing code

1. Load relevant reference files based on resource types and code patterns present.
2. Scan for NEVER rule violations — these are critical findings.
3. Check for missing ALWAYS requirements — these are high-priority findings.
4. Update `SECURITY-POSTURE.md` with a findings section listing each violation, severity, location, and remediation.
5. Offer to fix identified issues directly.

### Response format

Generated files should be clean. All reasoning is recorded in `SECURITY-POSTURE.md` instead, using this structure:

```markdown
## `path/to/file` — <Kind> (<date>)

**Controls applied:**
- `readOnlyRootFilesystem: true` + `emptyDir` at `/tmp` — feature requires writable temp dir; root FS locked down per pod-container-security Rule 5.
- `automountServiceAccountToken: false` — no K8s API access required.
- Integration test added at `tests/integration/test_<feature>.py` per correctness-test-coverage Rule 1.

**Additional steps required:**
- Create the API key Secret separately: `kubectl create secret generic ...`
```

When identifying issues during a review, append a findings section:

```markdown
## Validation Review: `<file>` (<date>)

> This audit is read-only. No files were modified.

### CRITICAL: [Issue Title]
- **Rule**: NEVER/ALWAYS reference (security or correctness)
- **Risk**: What could happen if not addressed
- **Recommended fix**: Exact remediation with a corrected snippet
```

## Quick reference: controls by resource type

| Resource type | Required controls |
|---|---|
| Deployment / Pod | SecurityContext, resources, serviceAccount, probes |
| Service | NetworkPolicy, no LoadBalancer without justification |
| Ingress | TLS, authentication annotation |
| Secret | Never in git, use `secretKeyRef` |
| ConfigMap | No secrets, validate content |
| ServiceAccount | Dedicated per workload, minimal RBAC |
| Role / ClusterRole | Least privilege, no wildcards |
| Dockerfile | Multi-stage, pinned images, no `curl \| bash` |
| Helm chart | Templated secrets, PDB, probes |
| New HTTP handler | Auth, input validation, integration test, env var matches Secret |
| New LLM/AI endpoint | Auth, input length limit, output filtered for PII, token budget, rate limiting |
| New SQL query | Aliases match consumer code, WHERE clause is required-or-explicit |
| New API response | Shape matches consumers, pagination fields present |

## Integration with the pre-push checklist

Before any code is committed, verify against `references/pre-push-checklist.md`. The checklist covers items from every domain (security and correctness) and can be copied directly into PR templates.
