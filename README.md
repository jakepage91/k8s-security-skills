# Kubernetes Validation Skills

A comprehensive collection of AI coding agent skills that enforce security best practices and catch code logic errors when generating or modifying code in Kubernetes environments. These skills act as persistent guardrails, automatically applying security rules and correctness checks when AI assistants generate Kubernetes manifests, Dockerfiles, application code, and Helm charts.

## Installation

### Via Claude Code Marketplace (recommended)

Add the marketplace, then install the plugin:

```bash
/plugin marketplace add jakepage91/k8s-security-skills
/plugin install k8s-security@metalbear-k8s
```

The skill activates automatically when generating Kubernetes-related code.

### Via --plugin-dir (local development)

Clone the repository and load it directly:

```bash
git clone https://github.com/jakepage91/k8s-security-skills
claude --plugin-dir ./k8s-security-skills
```

### Manual Integration

Reference in your `CLAUDE.md`, `.cursorrules`, or `copilot-instructions.md`:

```markdown
Always follow the rules defined in:
- k8s-security-skills/skills/k8s-security/SKILL.md
```

## Available Skills

| Skill | Description |
|-------|-------------|
| **k8s-security** | Comprehensive Kubernetes guardrails covering security, code logic, secrets, RBAC, networking, supply chain, and more |

## What This Validates

The k8s-security skill enforces NEVER/ALWAYS rules across 11 domains:

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

Once your code has been generated with the skill's guardrails applied, you can audit the whole repository or a specific app at any point:

```
/k8s-security:audit                  # audit entire repo
/k8s-security:audit llm-gateway/     # audit a specific app or directory
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

> Last audited: 2026-03-05 by k8s-security-skills

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
│   └── audit.md              # /k8s-security:audit slash command
└── skills/k8s-security/
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
