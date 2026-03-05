# Application Security Rules

> Version: 1.0 | Last Updated: 2026-03-05

## Rule 1: Authentication on Every Endpoint

**NEVER** expose endpoints without authentication, except `/healthz`, `/readyz`, `/metrics` (and only if metrics are on a separate internal port).

**ALWAYS** verify auth middleware is applied at the router/framework level, not per-handler. Check that no handler accidentally skips the auth chain.

Watch for: `@app.route` / `router.get` / `app.use` with no auth middleware; handlers that return data before calling `verify_token()` / `requireAuth()` / `authenticate`.

---

## Rule 2: No Sensitive Data in API Responses

**NEVER** return objects directly from the database/ORM — always use an explicit response schema or field allowlist.

Fields that must never appear in any response: `password`, `password_hash`, `secret`, `token`, `api_key`, `private_key`, `ssn`, `credit_card`, `cvv`, raw PII beyond what the caller needs.

Watch for: serialization of full model objects (`return user`, `res.json(record)`), `.dict()` / `JSON.stringify(row)` without field filtering, `SELECT *` results returned verbatim.

---

## Rule 3: Authorization (Not Just Authentication)

**NEVER** assume a logged-in user is authorized to access any resource by ID. Always verify the resource belongs to or is permitted for that user/role.

**ALWAYS** check `resource.owner == current_user.id` (or equivalent RBAC check) before returning or mutating any user-scoped resource.

Watch for: endpoints that accept an ID parameter and query the database without a `WHERE owner = ?` clause, or that only check `if not current_user` but not `if resource.owner != current_user.id`.

---

## Rule 4: Injection Prevention

**NEVER** interpolate user input directly into SQL queries, shell commands, LDAP filters, or log format strings.

**ALWAYS** use parameterized queries / prepared statements, ORMs with bound parameters, or `subprocess` with argument lists (not `shell=True`).

Watch for: f-strings or `%s %` string formatting in SQL; `os.system()`/`exec()`/`eval()` with any user-controlled value; `shell=True` with interpolated strings.

---

## Rule 5: No Internal Details in Error Responses

**NEVER** return stack traces, internal exception messages, database error text, file paths, or server version strings to clients.

**ALWAYS** log the full error internally and return a generic, structured error response (e.g. `{"error": "internal_error", "request_id": "..."}`).

Watch for: unhandled exception middleware that serializes `str(e)` or `traceback`, framework debug modes enabled in production (`DEBUG=True`, `NODE_ENV=development`).

---

## Rule 6: Input Validation and Pagination Bounds

**NEVER** trust client-supplied `limit`, `offset`, `page_size` without capping them. Unbounded pagination can leak full datasets or cause DoS.

**ALWAYS** enforce a maximum page size (e.g. 100 items) and validate that IDs and enum values are of the expected type/range before use.

Watch for: `limit = request.args.get('limit')` used directly in queries; no maximum enforced on list endpoints.

---

## Rule 7: No Secrets or PII in Logs

**NEVER** log request headers (`Authorization`, `Cookie`), request bodies that may contain passwords or PII, or internal token values.

**ALWAYS** use structured logging with an explicit field allowlist. Redact or omit sensitive fields before logging.

Watch for: `logger.debug(request.headers)`, `console.log(req.body)`, `print(payload)` in request handlers.
