# Kubernetes Validation Skills

A Claude Code plugin that validates Kubernetes manifests, application code, Dockerfiles, and Helm charts. The skill activates automatically when you generate Kubernetes-related code, applying NEVER/ALWAYS rules across two equal halves: **security** and **correctness**.

> The repo is named `k8s-security-skills` for historical reasons. The skill itself is `k8s-validation` and covers more than security alone.

## What it validates

### Security domains

- **Secrets management**: never hardcode secrets, always use Kubernetes Secrets or external secret managers.
- **Pod and container security**: SecurityContext hardening, resource limits, non-root execution.
- **Network exposure and Ingress**: authentication on endpoints, NetworkPolicies, TLS requirements.
- **Supply chain**: pinned dependencies, digest-pinned images, secure Dockerfiles.
- **Internal service auth**: service-to-service auth, mTLS, JWT validation.
- **File handling and path security**: path traversal prevention, input sanitization.
- **LLM and AI workload security**: OWASP LLM Top 10 compliance, prompt injection prevention, output PII filtering.
- **Helm and manifest generation**: secure templating, PodDisruptionBudgets, probes.
- **RBAC and ServiceAccounts**: least privilege, dedicated ServiceAccounts.
- **Observability and incident response**: secure logging, metrics, alerting.
- **App security**: app-layer auth, IDOR prevention, injection, output sanitization for external/LLM data.

### Correctness domains

- **HTTP and types**: parameter source matches HTTP method, type coercion at boundaries, environment-dependent code paths.
- **Data flow**: SQL aliases match downstream property access, WHERE clauses don't silently skip, request data reaches the query and the query result reaches the response.
- **API contracts**: response shapes match consumers, pagination math is correct, breaking changes are versioned.
- **Async and error handling**: missing `await` is flagged, error fallbacks don't swallow real failures.
- **Environment configuration**: env var names in code match Kubernetes Secret keys and Helm values, required config fails fast at startup.
- **Test coverage**: new endpoints ship with integration tests that exercise the actual risk, not just the happy path.

## How the skill shapes generation

When you ask the AI to add a new endpoint or feature, the skill instructs it to scan your existing codebase before generating anything — looking for auth decorators (`@require_auth`, `requireAuth`), sanitization utilities (`filter_pii`, `sanitize`), and error handling patterns. It uses what already exists rather than inventing new ones.

For example, given the prompt "add a `/summarise` endpoint that calls OpenAI's API", without the skill the model hardcodes the API key, skips auth, and returns the LLM response directly. With the skill loaded:

```python
import os
from openai import OpenAI
from utils.sanitize import filter_pii  # found by scanning the codebase

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

@app.route('/summarise', methods=['POST'])
@require_auth  # found by scanning the codebase
def summarise():
    text = request.json.get('text', '')
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Summarise: {text}"}],
    )
    summary = response.choices[0].message.content
    return jsonify({"summary": filter_pii(summary)})
```

Three differences: the key comes from an env var backed by a Kubernetes Secret, the endpoint sits behind the project's existing auth decorator, and the LLM output is filtered for PII before going back to the user.

## Installation

### Claude Code plugin (recommended)

```
/plugin install k8s-validation@jakepage91/k8s-security-skills
```

The skill activates automatically when generating Kubernetes-related code. The audit command becomes available as `/k8s-validation:audit`.

### Cursor

```bash
git clone https://github.com/jakepage91/k8s-security-skills.git .k8s-validation

cat >> .cursorrules << 'EOF'

## Validation Rules
Always read and follow the rules in .k8s-validation/skills/k8s-validation/SKILL.md
when generating or modifying Kubernetes manifests, Dockerfiles, Helm charts, or
application code that runs in Kubernetes.
EOF
```

### GitHub Copilot

```bash
git clone https://github.com/jakepage91/k8s-security-skills.git .k8s-validation

mkdir -p .github
cat >> .github/copilot-instructions.md << 'EOF'

## Validation Rules
Always read and follow the rules in .k8s-validation/skills/k8s-validation/SKILL.md.
EOF
```

## What you get

Installing the plugin gives you two things at once:

1. **The skill** (`k8s-validation`): NEVER/ALWAYS rules that load into the AI's context automatically when generating Kubernetes-related code. You don't invoke the skill; it just shapes what gets generated.
2. **The audit command** (`/k8s-validation:audit`): an explicit, invokable check you can run on your codebase (or a specific path) to find rule violations in code that already exists.

These map to two distinct validation layers: shaping what gets generated vs. checking what was generated. Skills are passive; commands are active. You use both.

## Auditing existing code

Audit the whole repository or a specific app at any point:

```
/k8s-validation:audit                  # audit entire repo
/k8s-validation:audit llm-gateway/     # audit a specific app or directory
```

The audit command:

1. Discovers Kubernetes manifests, Dockerfiles, Helm charts, CI/CD pipeline files, application code with HTTP endpoints, database queries, async patterns, and LLM/AI workload files.
2. Loads only the reference files relevant to what was found.
3. Reads application code files fully and traces data flow end-to-end.
4. Checks every file against applicable NEVER/ALWAYS rules from both security and correctness domains.
5. Classifies each finding by severity: **CRITICAL**, **HIGH**, **MEDIUM**, **INFO**.
6. Writes results to `SECURITY-POSTURE.md` in the project root with recommended fixes.

> The audit is read-only. It never modifies your code. Findings include concrete remediation snippets so you can apply fixes deliberately.

Example output:

```
CRITICAL 2 | HIGH 4 | MEDIUM 1 | INFO 0

[CRITICAL] src/routes/summarise.py — Hardcoded OpenAI API key → Use os.environ
[CRITICAL] src/routes/download.py — User filename in path without sanitization → Use secure_filename()
[HIGH]     src/routes/summarise.py — No authentication middleware → Add @require_auth
[HIGH]     k8s/deployment.yaml — No SecurityContext defined → Add runAsNonRoot, drop ALL
[HIGH]     src/routes/summarise.py — Reads OPENAI_API_KEY but no manifest defines it → Add to deployment.yaml env block
[HIGH]     src/routes/summarise.py — New endpoint with no integration test → Add test in tests/integration/
```

## Repository structure

```
.
├── commands/
│   └── audit.md                          # /k8s-validation:audit slash command
└── skills/k8s-validation/
    ├── SKILL.md                          # main skill instructions (auto-triggered)
    ├── README.md                         # skill documentation
    └── references/
        # security
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
        # correctness
        ├── correctness-http-and-types.md
        ├── correctness-data-flow.md
        ├── correctness-api-contracts.md
        ├── correctness-async-and-errors.md
        ├── correctness-environment-config.md
        ├── correctness-test-coverage.md
        # meta
        └── pre-push-checklist.md
```

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

If your AI assistant generates something the skill doesn't catch, [open a PR](https://github.com/jakepage91/k8s-security-skills/pulls).

## License

[MIT](LICENSE)
