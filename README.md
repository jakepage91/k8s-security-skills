# Kubernetes Security Skills

A comprehensive collection of AI coding agent skills that enforce security best practices when generating or modifying code in Kubernetes environments. These skills act as persistent security guardrails, automatically applying security rules when AI assistants generate Kubernetes manifests, Dockerfiles, application code, and Helm charts.

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
Always follow the security rules defined in:
- k8s-security-skills/skills/k8s-security/SKILL.md
```

## Available Skills

| Skill | Description |
|-------|-------------|
| **k8s-security** | Comprehensive Kubernetes security guardrails covering secrets, RBAC, networking, supply chain, and more |

## What This Enforces

The k8s-security skill enforces NEVER/ALWAYS rules across 10 critical security domains:

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

## How It Works

When installed, the skill automatically activates when you:

- Generate Kubernetes manifests (Deployments, Services, Ingress, etc.)
- Write Dockerfiles or container configurations
- Create Helm charts or Kustomize overlays
- Implement webhook handlers or API endpoints
- Configure service-to-service authentication
- Work with LLM/AI workloads in Kubernetes

The AI assistant will apply security rules and either:
- Generate secure code by default
- Flag security issues in existing code
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
User: "Add database credentials to my app"

AI: [Generates]:
- Kubernetes Secret manifest (with placeholder for actual values)
- Environment variables using secretKeyRef
- Fail-fast startup validation code
- Warning about never committing actual secret values
```

## Auditing Existing Manifests

Once your code has been generated with the skill's guardrails applied, you can audit the whole repository or a specific app at any point:

```
/k8s-security:audit                  # audit entire repo
/k8s-security:audit llm-gateway/     # audit a specific app or directory
```

The audit command:
1. Discovers all Kubernetes manifests, Dockerfiles, Helm charts, and CI/CD pipeline files
2. Checks every file against all 10 security domains (NEVER/ALWAYS rules)
3. Classifies each finding by severity: **CRITICAL**, **HIGH**, **MEDIUM**, **INFO**
4. Writes results to `SECURITY-POSTURE.md` in the project root with recommended fixes
5. Outputs a summary of finding counts and the top 3 most urgent issues

> **Read-only**: the audit never modifies your manifests. Findings include concrete remediation snippets so you can apply fixes deliberately when ready — this matters when manifests are already running in production.

Example `SECURITY-POSTURE.md` output:

```markdown
# Kubernetes Security Posture

> Last audited: 2026-03-03 by k8s-security-skills

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2     |
| HIGH     | 5     |
| MEDIUM   | 3     |
| INFO     | 1     |

## Findings by File

### `k8s/deployment.yaml`

#### CRITICAL: Hardcoded API key in environment variable
- **Rule**: secrets-management Rule 1
- **Location**: spec.containers[0].env[2].value
- **Risk**: Secret exposed in version control and cluster etcd
- **Recommended fix**: Use secretKeyRef instead — `kubectl create secret generic api-key --from-literal=key=<value>`
```

## Skill Components

```
.
├── commands/
│   └── audit.md              # /k8s-security:audit slash command
└── skills/k8s-security/
    ├── SKILL.md              # Main skill instructions (auto-triggered)
    ├── README.md             # Skill documentation
    └── references/           # Detailed security rules
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
        └── pre-push-checklist.md
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](LICENSE)