# Application Security Rules

> Version: 2.0 | Last Updated: 2026-05-20

## Rule 1: Authentication on Every Endpoint

**NEVER** expose endpoints without authentication, except `/healthz`, `/readyz`, `/metrics` (and only if metrics are on a separate internal port).

**ALWAYS** verify auth middleware is applied at the router/framework level, not per-handler. Check that no handler accidentally skips the auth chain.

Watch for: `@app.route` / `router.get` / `app.use` with no auth middleware; handlers that return data before calling `verify_token()` / `requireAuth()` / `authenticate`.

Before generating a new auth mechanism, **search the codebase** for existing decorators and middleware (`@require_auth`, `@login_required`, `requireAuth`, `authenticate`, `verifyToken`, `authMiddleware`). Use what already exists.

```python
# WRONG - No auth check
@app.route('/summarise', methods=['POST'])
def summarise():
    text = request.json.get('text', '')
    return jsonify({"summary": summarize_text(text)})

# CORRECT - Auth applied via decorator (use the project's existing decorator)
@app.route('/summarise', methods=['POST'])
@require_auth  # search the codebase for the existing decorator before inventing one
def summarise():
    text = request.json.get('text', '')
    return jsonify({"summary": summarize_text(text)})
```

```python
# FastAPI - WRONG
@router.post("/users/{user_id}/data")
def get_user_data(user_id: str):
    return db.get_user(user_id)

# FastAPI - CORRECT
@router.post("/users/{user_id}/data")
def get_user_data(user_id: str, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403)
    return db.get_user(user_id)
```

```javascript
// Express - WRONG: auth only on some routes
router.get('/public', publicHandler)
router.get('/data', dataHandler)  // Missing auth middleware

// Express - CORRECT: auth applied at router level
const apiRouter = express.Router()
apiRouter.use(authenticate)  // applies to all routes below
apiRouter.get('/data', dataHandler)
```

```go
// Go - CORRECT: auth middleware wraps the mux
mux := http.NewServeMux()
mux.HandleFunc("/summarise", summariseHandler)
http.ListenAndServe(":8080", authMiddleware(mux))
```

---

## Rule 2: No Sensitive Data in API Responses

**NEVER** return objects directly from the database/ORM — always use an explicit response schema or field allowlist.

Fields that must never appear in any response: `password`, `password_hash`, `secret`, `token`, `api_key`, `private_key`, `ssn`, `credit_card`, `cvv`, raw PII beyond what the caller needs.

Watch for: serialization of full model objects (`return user`, `res.json(record)`), `.dict()` / `JSON.stringify(row)` without field filtering, `SELECT *` results returned verbatim.

```python
# WRONG - Returns entire model including password_hash, api_key, etc.
@app.route('/users/<user_id>')
@require_auth
def get_user(user_id):
    user = db.session.get(User, user_id)
    return jsonify(user.__dict__)  # exposes every column

# CORRECT - Explicit field allowlist using a response schema
class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    created_at: datetime
    # password_hash, api_key, ssn intentionally excluded

@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, current_user: User = Depends(get_current_user)):
    user = db.get_user(user_id)
    return UserResponse.from_orm(user)
```

```javascript
// WRONG - Spreads entire database row including secrets
app.get('/users/:id', async (req, res) => {
    const user = await db.users.findOne({ id: req.params.id })
    res.json(user)  // includes password_hash, token, etc.
})

// CORRECT - Destructure only the fields consumers need
app.get('/users/:id', authenticate, async (req, res) => {
    const user = await db.users.findOne({ id: req.params.id })
    const { id, name, email, createdAt } = user  // explicit allowlist
    res.json({ id, name, email, createdAt })
})
```

---

## Rule 3: Authorization (Not Just Authentication)

**NEVER** assume a logged-in user is authorized to access any resource by ID. Always verify the resource belongs to or is permitted for that user/role (Insecure Direct Object Reference — IDOR prevention).

**ALWAYS** check `resource.owner == current_user.id` (or equivalent RBAC check) before returning or mutating any user-scoped resource.

Watch for: endpoints that accept an ID parameter and query the database without a `WHERE owner = ?` clause, or that only check `if not current_user` but not `if resource.owner != current_user.id`.

```python
# WRONG - Fetches any resource by ID regardless of ownership
@app.route('/documents/<doc_id>')
@require_auth
def get_document(doc_id):
    doc = Document.query.get(doc_id)  # any user can access any doc
    return jsonify(doc.to_dict())

# CORRECT - Enforce ownership at the query level
@app.route('/documents/<doc_id>')
@require_auth
def get_document(doc_id):
    doc = Document.query.filter_by(
        id=doc_id,
        owner_id=current_user.id  # ownership enforced in WHERE clause
    ).first_or_404()
    return jsonify(doc.to_dict())
```

```javascript
// WRONG - ID-based lookup without owner check
router.get('/orders/:id', authenticate, async (req, res) => {
    const order = await db.orders.findOne({ id: req.params.id })
    res.json(order)
})

// CORRECT - Ownership enforced at query level
router.get('/orders/:id', authenticate, async (req, res) => {
    const order = await db.orders.findOne({
        id: req.params.id,
        userId: req.user.id  // only returns the row if it belongs to this user
    })
    if (!order) return res.status(404).json({ error: 'not_found' })
    res.json(order)
})
```

---

## Rule 4: Injection Prevention

**NEVER** interpolate user input directly into SQL queries, shell commands, LDAP filters, or log format strings.

**ALWAYS** use parameterized queries / prepared statements, ORMs with bound parameters, or `subprocess` with argument lists (not `shell=True`).

Watch for: f-strings or `%s %` string formatting in SQL; `os.system()`/`exec()`/`eval()` with any user-controlled value; `shell=True` with interpolated strings.

```python
# WRONG - SQL injection via f-string
def get_user_by_name(name: str):
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")

# CORRECT - Parameterized query
def get_user_by_name(name: str):
    return db.execute("SELECT * FROM users WHERE name = %s", (name,))
```

```python
# WRONG - Shell injection
import subprocess
def run_job(job_name: str):
    subprocess.run(f"kubectl get pod {job_name}", shell=True)  # injection via job_name

# CORRECT - Argument list, no shell
def run_job(job_name: str):
    subprocess.run(["kubectl", "get", "pod", job_name], shell=False)
```

```javascript
// WRONG - SQL injection via template literal
async function getUser(name) {
    return db.query(`SELECT * FROM users WHERE name = '${name}'`)
}

// CORRECT - Parameterized query
async function getUser(name) {
    return db.query('SELECT * FROM users WHERE name = $1', [name])
}
```

```go
// WRONG - SQL injection via fmt.Sprintf
func getUser(name string) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}

// CORRECT - Parameterized query
func getUser(name string) {
    db.Query("SELECT * FROM users WHERE name = $1", name)
}
```

---

## Rule 5: No Internal Details in Error Responses

**NEVER** return stack traces, internal exception messages, database error text, file paths, or server version strings to clients.

**ALWAYS** log the full error internally and return a generic, structured error response (e.g. `{"error": "internal_error", "request_id": "..."}`).

Watch for: unhandled exception middleware that serializes `str(e)` or `traceback`, framework debug modes enabled in production (`DEBUG=True`, `NODE_ENV=development`).

```python
# WRONG - Returns internal error details
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

# CORRECT - Log internally, return structured generic response
import uuid

@app.errorhandler(Exception)
def handle_error(e):
    request_id = str(uuid.uuid4())
    logger.error("Unhandled exception", exc_info=e, extra={"request_id": request_id})
    return jsonify({"error": "internal_error", "request_id": request_id}), 500
```

```javascript
// WRONG - Exposes internal error details
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack })
})

// CORRECT - Log full error, return generic response
app.use((err, req, res, next) => {
    const requestId = crypto.randomUUID()
    logger.error({ err, requestId }, 'Unhandled error')
    res.status(500).json({ error: 'internal_error', requestId })
})
```

Also verify production flag is set. In Flask: `app.config['DEBUG'] = False`. In Express: `NODE_ENV=production` (disables detailed error pages).

---

## Rule 6: Input Validation and Pagination Bounds

**NEVER** trust client-supplied `limit`, `offset`, `page_size` without capping them. Unbounded pagination can leak full datasets or cause DoS.

**ALWAYS** enforce a maximum page size (e.g. 100 items) and validate that IDs and enum values are of the expected type/range before use.

Watch for: `limit = request.args.get('limit')` used directly in queries; no maximum enforced on list endpoints.

```python
# WRONG - No bounds, no type conversion
@app.route('/items')
@require_auth
def list_items():
    limit = request.args.get('limit')
    offset = request.args.get('offset')
    return db.execute(f"SELECT * FROM items LIMIT {limit} OFFSET {offset}")

# CORRECT - Validated, capped, type-safe
MAX_PAGE_SIZE = 100

@app.route('/items')
@require_auth
def list_items():
    try:
        limit = min(int(request.args.get('limit', 20)), MAX_PAGE_SIZE)
        offset = max(int(request.args.get('offset', 0)), 0)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_pagination"}), 400
    items = db.execute("SELECT * FROM items LIMIT %s OFFSET %s", (limit, offset))
    return jsonify({"items": [i.to_dict() for i in items], "limit": limit, "offset": offset})
```

```typescript
// Correct - Zod schema enforces bounds at parse time
const PaginationSchema = z.object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    offset: z.coerce.number().int().min(0).default(0),
})

router.get('/items', authenticate, async (req, res) => {
    const { limit, offset } = PaginationSchema.parse(req.query)
    const items = await db.items.findMany({ take: limit, skip: offset })
    res.json({ items, limit, offset })
})
```

---

## Rule 7: No Secrets or PII in Logs

**NEVER** log request headers (`Authorization`, `Cookie`), request bodies that may contain passwords or PII, or internal token values.

**ALWAYS** use structured logging with an explicit field allowlist. Redact or omit sensitive fields before logging.

Watch for: `logger.debug(request.headers)`, `console.log(req.body)`, `print(payload)` in request handlers.

```python
# WRONG - Logs entire request including auth headers and body
@app.before_request
def log_request():
    logger.debug(f"Request: {request.headers} {request.get_json()}")

# CORRECT - Log only safe fields
@app.before_request
def log_request():
    logger.info("Request received", extra={
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent"),
        # Authorization, Cookie, X-API-Key intentionally omitted
    })
```

```javascript
// WRONG - Logs full request body which may contain passwords
app.use((req, res, next) => {
    console.log(req.body)  // may contain { password: "...", ssn: "..." }
    next()
})

// CORRECT - Allowlist-based request logging
app.use((req, res, next) => {
    logger.info({ method: req.method, path: req.path, userId: req.user?.id }, 'request')
    // body is intentionally not logged
    next()
})
```

---

## Rule 8: Output Sanitization for External Data

**NEVER** return raw output from LLMs, external APIs, or user-generated content without sanitizing it first.

**ALWAYS** search the codebase for an existing sanitization utility (`filter_pii`, `sanitize_output`, `redact`, `scrub`) before writing a new one. Use what already exists.

Watch for: `return jsonify({"summary": llm_response})` where `llm_response` is raw LLM output; `res.json({ content: externalApiResponse.data })` with no field filtering.

```python
# WRONG - Returns raw LLM output that may contain PII from the prompt context
@app.route('/summarise', methods=['POST'])
@require_auth
def summarise():
    text = request.json.get('text', '')
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Summarise: {text}"}],
    )
    return jsonify({"summary": response.choices[0].message.content})  # WRONG - raw output

# CORRECT - Filter before returning (use the project's existing utility)
from utils.sanitize import filter_pii  # search the codebase for this first

@app.route('/summarise', methods=['POST'])
@require_auth
def summarise():
    text = request.json.get('text', '')
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Summarise: {text}"}],
    )
    summary = response.choices[0].message.content
    return jsonify({"summary": filter_pii(summary)})
```

For LLM workloads, also see `references/llm-ai-security.md` for the complete rule set (prompt injection, token limits, tool access controls).
