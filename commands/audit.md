---
description: Run a full Kubernetes security audit of the current repository and write findings to SECURITY-POSTURE.md
---

You are performing a comprehensive Kubernetes security audit of this repository. Follow these steps precisely:

## Step 1: Discover all resources to audit

Search the repository for:
- All Kubernetes manifests (`**/*.yaml`, `**/*.yml`) that contain `kind:` fields
- All Dockerfiles (`**/Dockerfile*`)
- All Helm charts (`**/Chart.yaml`)
- Any CI/CD pipeline files that deploy to Kubernetes (`.github/workflows/*.yml`, etc.)

List each file found before proceeding.

## Step 2: Load all reference files

Load every reference file from this skill:
- `references/secrets-management.md`
- `references/pod-container-security.md`
- `references/network-exposure.md`
- `references/supply-chain-security.md`
- `references/internal-service-auth.md`
- `references/file-handling-security.md`
- `references/llm-ai-security.md`
- `references/helm-manifest-security.md`
- `references/rbac-service-accounts.md`
- `references/observability-incident-response.md`

## Step 3: Audit each file

For each discovered file, check every applicable NEVER/ALWAYS rule. Classify each finding as:

- **CRITICAL** — a NEVER rule is violated (e.g. hardcoded secret, privileged: true, wildcard RBAC)
- **HIGH** — a required ALWAYS control is missing (e.g. no SecurityContext, no resource limits, no NetworkPolicy)
- **MEDIUM** — a best-practice gap that increases risk but is not an immediate violation
- **INFO** — an observation or improvement opportunity

## Step 4: Write SECURITY-POSTURE.md

Create or update `SECURITY-POSTURE.md` in the project root with the full audit results using this structure. Then ensure `SECURITY-POSTURE.md` is listed in `.gitignore` — append the entry if missing, creating `.gitignore` if it does not exist.

```markdown
# Kubernetes Security Posture

> Last audited: <date> by k8s-security-skills

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | N |
| HIGH     | N |
| MEDIUM   | N |
| INFO     | N |

---

## Findings by File

### `<path/to/file.yaml>`

#### CRITICAL: <Finding title>
- **Rule**: NEVER rule reference (e.g. secrets-management Rule 1)
- **Location**: line number or field path
- **Risk**: What an attacker could do if this is not fixed
- **Fix**: Exact remediation with corrected YAML/code snippet

#### HIGH: <Finding title>
...

---

## Files with no findings

- `path/to/clean-file.yaml` — all controls present
```

## Step 5: Summarise and recommend

After writing SECURITY-POSTURE.md, output a concise summary in the chat:

- The total finding counts by severity
- The top 3 most urgent issues with a one-line description of each
- A reminder that **no files have been modified** — this audit is read-only

Do NOT auto-fix anything. The manifests may be running in production and changes require a deliberate deployment process. Instead, for each CRITICAL and HIGH finding, include a concrete recommendation in SECURITY-POSTURE.md under a `**Recommended fix:**` field so the user has everything they need to act when ready.

If the user explicitly asks to fix a specific finding after the audit, address it then — one file at a time, with the user's confirmation before writing.
