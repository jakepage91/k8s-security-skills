# Kubernetes Validation Skills

A comprehensive collection of AI coding agent skills that validate Kubernetes manifests, application code, Dockerfiles, and Helm charts. These skills act as persistent guardrails — catching security misconfigurations, code logic errors, and data-flow bugs before they reach production.

## Installation

### Claude Code Plugin (recommended)

```bash
/plugin install k8s-validation@jakepage91/k8s-security-skills
```

The skill activates automatically when generating Kubernetes-related code. The audit command becomes available as `/k8s-validation:audit`.

### Via --plugin-dir (local development)

Clone the repository and load it directly:

```bash
git clone https://github.com/jakepage91/k8s-security-skills
claude --plugin-dir ./k8s-security-skills
```

## Available Skills

| Skill | Description |
|-------|-------------|
| **k8s-validation** | Kubernetes guardrails covering security, code logic, data-flow correctness, secrets, RBAC, networking, supply chain, and more |

## What This Validates

The k8s-validation skill enforces NEVER/ALWAYS rules across 11 domains:

### Security
1. **Secrets Management** - Never hardcode secrets, always use Kubernetes Secrets or external secret managers
2. **Pod & Container Security** - SecurityContext hardening, resource limits, non-root execution
3. **Network Exposure & Ingress** - Authentication on endpoints, NetworkPolicies, TLS requirements
4. **Supply Chain Security** - Pinned dependencies, digest-pinned images, secure Dockerfiles
5. **Internal Service Authentication** - Service-to-service auth, mTLS, JWT validation
6. **File Handling & Path Security** - Path traversal prevention, input sanitization
7. **LLM & AI Workload Security** - OWASP LLM Top 10 compliance
8. **Helm & Manifest Generation** - Secure templating, PodDisruptionBudgets, probes
9. **RBAC & Service Accounts** - Least privilege, dedicated service accounts
10. **Observability & Incident Response** - Secure logging, metrics, alerting

### Code Logic & Correctness
11. **Code Logic** - HTTP method/parameter source mismatches, SQL alias/app code mismatches, silently skipped WHERE clauses, response shape mismatches, async/await errors, end-to-end data flow verification

## How It Works

When installed, the skill automatically activates when you:

- Generate Kubernetes manifests (Deployments, Services, Ingress, etc.)
- Write Dockerfiles or container configurations
- Create Helm charts or Kustomize overlays
- Implement webhook handlers or API endpoints
- Write database queries or ORM code
- Configure service-to-service authentication
- Work with LLM/AI workloads in Kubernetes

The AI assistant will:
- Generate secure, correct code by default
- Flag security issues and logic bugs in existing code
- Trace data flow from request input through queries to response output
- Suggest remediations with correct/incorrect examples

## Example Usage

```
User: "Create a deployment for my Python API"

AI: [Generates deployment with]:
- runAsNonRoot: true
- readOnlyRootFilesystem: true
- allowPrivilegeEscalation: false
- Resource requests and limits
- Dedicated ServiceAccount
- automountServiceAccountToken: false
- Liveness and readiness probes
```

```
User: "Add a GET endpoint that filters by conference"

AI: [Validates]:
- Parameters read from req.query (not req.body) for GET requests
- SQL column aliases match the JS property names used downstream
- WHERE clause doesn't silently return all rows when filter param is missing
```

## Auditing Existing Code

Audit the whole repository or a specific app at any point:

```
/k8s-validation:audit                  # audit entire repo
/k8s-validation:audit llm-gateway/     # audit a specific app or directory
```

The audit command:
1. Discovers all Kubernetes manifests, Dockerfiles, Helm charts, CI/CD pipeline files, and application code with HTTP endpoints or database queries
2. Loads only the reference files relevant to what was found
3. **Reads application code files fully** and traces data flow end-to-end
4. Checks every file against applicable NEVER/ALWAYS rules (security + code logic)
5. Classifies each finding by severity: **CRITICAL**, **HIGH**, **MEDIUM**, **INFO**
6. Writes results to `SECURITY-POSTURE.md` in the project root with recommended fixes

> **Read-only**: the audit never modifies your code. Findings include concrete remediation snippets so you can apply fixes deliberately.

Example `SECURITY-POSTURE.md` output:

```markdown
# Security Posture

> Last audited: 2026-03-05 by k8s-validation

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| HIGH     | 5     |
| MEDIUM   | 2     |
| INFO     | 1     |

## Findings

| Sev | File | Issue | Fix |
|-----|------|-------|-----|
| CRITICAL | `k8s/deployment.yaml` | Hardcoded API key in env | Use secretKeyRef |
| CRITICAL | `src/routes/feed.js:18` | req.body in GET handler — filter silently skipped | Change to req.query |
| CRITICAL | `src/routes/feed.js:39` | SQL column not aliased — JS reads r.slug but query returns r.conference | Add AS slug |
```

## Skill Components

```
.
├── commands/
│   └── audit.md              # /k8s-validation:audit slash command
└── skills/k8s-validation/
    ├── SKILL.md              # Main skill instructions (auto-triggered)
    ├── README.md             # Skill documentation
    └── references/           # Detailed rules
        ├── secrets-management.md
        ├── pod-container-security.md
        ├── network-exposure.md
        ├── supply-chain-security.md
        ├── internal-service-auth.md
        ├── file-handling-security.md
        ├── llm-ai-security.md
        ├── helm-manifest-security.md
        ├── rbac-service-accounts.md
        ├── observability-incident-response.md
        ├── app-security.md
        ├── code-logic.md
        └── pre-push-checklist.md
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](LICENSE)
