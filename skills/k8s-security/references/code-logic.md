# Code Logic & Correctness Rules

> Version: 1.0 | Last Updated: 2026-03-05

These rules catch common logic bugs in application code — the kind that pass code review but break at runtime with real data. Many are introduced by LLM-generated code that pattern-matches from surrounding context without tracing the full data flow.

---

## Rule 1: HTTP Method / Parameter Source Mismatch

**NEVER** read parameters from a source that doesn't match the HTTP method.

- `GET` / `DELETE` requests: parameters come from `req.query` (Express), `request.args` (Flask), query string parsers, or URL path params — **not** from `req.body` / `request.json`.
- `POST` / `PUT` / `PATCH` requests: parameters come from `req.body` / `request.json` / form data.

Watch for: `req.body` in a `router.get()` or `app.get()` handler; `request.json` in a `@app.route(..., methods=['GET'])` handler; `req.query` in a `router.post()` handler when body params were intended.

Why it matters: The handler silently receives `undefined` / `None` for every parameter, causing filters and conditions to be skipped. No error is thrown — the code just returns wrong results.

---

## Rule 2: SQL Column Alias / Application Code Mismatch

**ALWAYS** verify that SQL column names or aliases match the property names used in downstream application code.

Watch for:
- `SELECT column_name ...` where JS/Python code accesses `row.different_name` or `row['different_name']`
- Missing `AS alias` when the application expects a specific key (e.g., `SELECT conference, COUNT(*)` but code reads `r.slug`)
- ORM `.select()` or `.raw()` queries where the returned field names don't match destructuring or property access

Why it matters: The mismatch produces `undefined` / `None` values silently — no error, just wrong data (zeros, nulls, empty lists).

---

## Rule 3: WHERE Clause Silently Skipped

**NEVER** build conditional WHERE clauses that silently become no-ops when input is missing.

Watch for:
- `if (param) query += ' WHERE col = ?'` — when `param` is `undefined`/`null`/`""`, the query returns all rows instead of none or an error
- ORM patterns like `.where(param ? { col: param } : {})` — an empty filter returns everything
- Conditional `.filter()` that falls through to unfiltered queries

**ALWAYS** either: (a) validate required filter parameters before querying and return 400 if missing, or (b) explicitly handle the "no filter" case with documented intent.

Why it matters: Missing filters silently return the entire dataset, causing data leakage across tenants, conferences, orgs, etc.

---

## Rule 4: Response Shape / Consumer Contract Mismatch

**ALWAYS** verify that the shape of API responses matches what consumers (frontend code, other services) actually destructure or access.

Watch for:
- Backend returns `{ items: [...] }` but frontend reads `response.data.results`
- Endpoint returns a flat array but consumer expects `{ data: [...], total: N }`
- Field renamed on backend (`name` -> `title`) without updating all consumers
- Pagination response missing `total`, `next_page`, or `has_more` that the frontend relies on

Why it matters: Shape mismatches cause silent failures — components render empty, counts show 0, pagination breaks.

---

## Rule 5: Async / Await and Promise Handling

**NEVER** omit `await` on async database queries, HTTP calls, or file operations when the result is used synchronously.

Watch for:
- `const result = db.query(...)` without `await` — `result` is a Promise, not a result set
- `if (fetchUser(id))` where `fetchUser` is async — the Promise is always truthy
- `.then()` chains that don't return the inner promise, losing the result
- `try/catch` around an un-awaited async call — errors are not caught

**ALWAYS** ensure every async call that produces a needed value is properly awaited or chained.

---

## Rule 6: Off-by-One and Boundary Errors in Pagination / Slicing

**ALWAYS** verify pagination math: `offset + limit` logic, zero-based vs one-based page numbers, and edge cases (empty result, last page).

Watch for:
- `offset = page * limit` when page is 1-based (skips the first page of results)
- `LIMIT` and `OFFSET` swapped in SQL
- Array `.slice(start, end)` where `end` is exclusive but treated as inclusive
- Missing `Math.ceil` in total page count calculation

---

## Rule 7: Environment-Dependent Code Paths

**NEVER** assume runtime environment matches development assumptions.

Watch for:
- Code that works with in-memory/SQLite DB but fails on Postgres/MySQL (e.g., different type coercion, case sensitivity, JSON handling)
- Relying on object key ordering (not guaranteed in JS for numeric keys)
- Locale-dependent string comparisons or date parsing
- File paths that assume a specific OS (hardcoded `/` vs `\`)

---

## Rule 8: Type Coercion and Comparison Bugs

**ALWAYS** use strict equality and explicit type conversion at system boundaries.

Watch for:
- `==` instead of `===` in JavaScript (e.g., `id == req.params.id` where one is a number and one is a string)
- Comparing database integer IDs with string URL params without parsing
- `Boolean("false") === true` in JS — string "false" is truthy
- Python `if value:` when `value` could be `0` or `""` (both falsy but valid)

---

## Rule 9: Error Handling That Swallows Context

**NEVER** catch errors and silently continue with default/fallback values that hide the real failure.

Watch for:
- `catch (e) { return [] }` — caller thinks "no results" when the real issue is a database connection failure
- `try { ... } catch { }` — empty catch blocks that swallow all errors
- Default values in destructuring that mask missing data: `const { items = [] } = response` hiding a broken API call
- `|| []` fallbacks that hide undefined responses

---

## Rule 10: Data Flow Across Query Boundaries

**ALWAYS** trace data from input (request params, env vars, config) through processing (queries, transformations) to output (response, UI) to verify the full pipeline is connected.

Watch for:
- A variable is read from the request but never passed into the query
- A query result field is selected but never included in the API response
- Middleware sets a value on `req` (e.g., `req.user`) but the handler reads it from a different property (e.g., `req.currentUser`)
- Config values read at startup but the env var name is misspelled (silent `undefined`)
