# Kubernetes Security Skills

A comprehensive collection of AI coding agent skills that enforce security best practices when generating or modifying code in Kubernetes environments. These skills act as persistent security guardrails, automatically applying security rules when AI assistants generate Kubernetes manifests, Dockerfiles, application code, and Helm charts.

## Installation

### Claude Code Plugin (recommended)

Clone the repository and load it with the `--plugin-dir` flag:

```bash
git clone https://github.com/metalbear-co/k8s-security-skills
claude --plugin-dir ./k8s-security-skills
```

The skill is then available as `/k8s-security-skills:k8s-security`.

To load it permanently across all sessions, add it to your Claude Code user settings (`~/.claude/settings.json`):

```json
{
  "plugins": [
    { "source": "/path/to/k8s-security-skills" }
  ]
}
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

## Skill Components

```
skills/k8s-security/
├── SKILL.md              # Main skill instructions
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