---
description: Run a Kubernetes best-practices audit (security, code logic, correctness) and write findings to SECURITY-POSTURE.md. Optionally scope to a specific path: /k8s-validation:audit llm-gateway/
---

You are performing a comprehensive Kubernetes best-practices audit covering security, code correctness, and logic errors. Follow these steps precisely:

## Step 0: Determine scope

Check whether a path argument was provided (e.g. `/k8s-validation:audit llm-gateway/`).

- **If a path was provided**: restrict all discovery and auditing to that directory. Note the scope at the top of SECURITY-POSTURE.md: `> Scope: <path>`.
- **If no path was provided**: audit the entire repository from the root.

## Step 1: Discover all resources to audit

Within the determined scope, search for:
- All Kubernetes manifests (`**/*.yaml`, `**/*.yml`) that contain `kind:` fields
- All Dockerfiles (`**/Dockerfile*`)
- All Helm charts (`**/Chart.yaml`)
- Any CI/CD pipeline files that deploy to Kubernetes (`.github/workflows/*.yml`, etc.)
- Application code: search for files containing route/endpoint definitions using patterns like `@app.route`, `router.get`, `router.post`, `app.get`, `app.post`, `@router.`, `func.*Handler`, `http.HandleFunc` in `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`, `**/*.rb`. Do **not** read all app files — only grep for these patterns to find files that define HTTP endpoints.
- Application code with database queries: search for files containing SQL queries or ORM calls using patterns like `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `db.query`, `pool.query`, `.execute(`, `.raw(`, `knex(`, `prisma.`, `sequelize.` in the same file types. These are candidates for logic-bug analysis.
- LLM/AI workload files: search for files containing `openai`, `anthropic`, `langchain`, `llm`, `chat.completions`, `embeddings`, `prompt`, `generate_content`, `GenerativeModel` in the same file types. These require LLM-specific security checks on top of standard app security.

List each file found before proceeding.

## Step 2: Load only the relevant reference files

Based on what was found in Step 1, load only the reference files that apply. Do **not** load references for artifact types that were not discovered.

| Condition | Load |
|---|---|
| Any k8s manifest found | `references/secrets-management.md` |
| Any manifest with `kind: Deployment`, `Pod`, `DaemonSet`, `StatefulSet`, `Job`, or `CronJob` | `references/pod-container-security.md` |
| Any manifest with `kind: Service`, `Ingress`, or `NetworkPolicy` | `references/network-exposure.md` |
| Any manifest with `kind: Role`, `ClusterRole`, `RoleBinding`, or `ClusterRoleBinding`; or any `serviceAccountName` reference | `references/rbac-service-accounts.md` |
| Any `Dockerfile*` or CI/CD pipeline file found | `references/supply-chain-security.md` |
| Any `Chart.yaml` (Helm chart) found | `references/helm-manifest-security.md` |
| Any manifest or code file referencing inter-service auth, mTLS, JWT, or service mesh annotations | `references/internal-service-auth.md` |
| Any application code with HTTP endpoint definitions found | `references/app-security.md`, `references/correctness-http-and-types.md`, `references/correctness-api-contracts.md`, `references/correctness-test-coverage.md` |
| Any application code with database queries found | `references/correctness-data-flow.md` |
| Any application code with async/await patterns or error handling found | `references/correctness-async-and-errors.md` |
| Any application code that reads environment variables, OR any manifest with `env` blocks, OR any Helm chart with `values.yaml` | `references/correctness-environment-config.md` |
| Any application code with file upload or file path operations (`send_file`, `open(`, `fs.readFile`, `os.path`, `filepath.Join`) | `references/file-handling-security.md` |
| Any file with LLM/AI indicators: filenames or content containing `llm`, `openai`, `anthropic`, `langchain`, `embeddings`, `prompt`, `completion` | `references/llm-ai-security.md` |
| Any k8s manifest or application code found (i.e. almost always) | `references/observability-incident-response.md` |

List which reference files were loaded and which were skipped (with the reason) before proceeding.

## Step 3: Audit each file

For each discovered file, check every applicable NEVER/ALWAYS rule from both security and code-logic references. **Read application code files fully** — do not just grep for patterns. Trace data flow from request input through query construction to response output.

### Security checks
Apply all NEVER/ALWAYS rules from security reference files (secrets, pod security, RBAC, etc.).

### Correctness checks (for application code files)
For every HTTP handler, route, or background job, verify:
1. **Parameter source matches HTTP method** — `req.body` only in POST/PUT/PATCH, `req.query`/`req.params` in GET/DELETE.
2. **SQL aliases match downstream property access** — if JS reads `row.slug`, the SQL must `SELECT ... AS slug`.
3. **WHERE clauses are not silently skipped** — conditional filters must validate required params, not silently return all rows.
4. **Response shape matches consumer expectations** — field names in the response must match what frontend/callers destructure.
5. **Async operations are properly awaited** — database calls, HTTP requests, file I/O.
6. **Errors are not silently swallowed** — `catch { return [] }` and similar patterns hide real failures and must be flagged.
7. **Data flows end-to-end** — a request param that's read must actually reach the query; a query result field must reach the response.
8. **Environment variable names match the cluster** — for any `os.environ[...]` / `process.env.X` access, check whether a manifest in the repo defines the same name in an `env` block or `secretKeyRef`. Flag mismatches.
9. **New endpoints have integration tests** — if a handler exists with no corresponding test in `tests/integration/` (or the project's equivalent), flag it.

Classify each finding as:

- **CRITICAL** — a NEVER rule is violated (security: hardcoded secret, privileged: true, wildcard RBAC; correctness: wrong parameter source, missing SQL alias, skipped WHERE clause, swallowed errors).
- **HIGH** — a required ALWAYS control is missing (security: no SecurityContext, no resource limits, no NetworkPolicy; correctness: env var name mismatch with the cluster, no integration test for a new handler, response shape mismatch with a known consumer).
- **MEDIUM** — a best-practice gap that increases risk but is not an immediate violation.
- **INFO** — an observation or improvement opportunity.

## Step 4: Output findings

Output findings directly in chat using this compact format, then write a minimal `SECURITY-POSTURE.md`. Ensure `SECURITY-POSTURE.md` is in `.gitignore`.

**Chat output** — severity table then one line per finding:

```
CRITICAL N | HIGH N | MEDIUM N | INFO N

[CRITICAL] path/to/file.yaml — Finding title (rule ref) → one-line fix
[HIGH]     path/to/file.yaml — Finding title (rule ref) → one-line fix
...
```

Only include MEDIUM/INFO if there are no CRITICAL/HIGH findings, or append them briefly after.

**SECURITY-POSTURE.md** — minimal file:

```markdown
# Security Posture
> <date> · Scope: <path or "repo">

| Severity | Count |
|----------|-------|
| CRITICAL | N |
| HIGH     | N |
| MEDIUM   | N |
| INFO     | N |

## Findings

| Sev | File | Issue | Fix |
|-----|------|-------|-----|
| CRITICAL | `file.yaml` | Finding title | One-line remediation |
| HIGH | `file.yaml` | Finding title | One-line remediation |
```

Do NOT auto-fix anything. If the user asks to fix a specific finding after the audit, address it one file at a time with their confirmation.
