# Python + FastAPI — Misconfigurations & Common Vulnerabilities

Defensive reference for FastAPI services.

---

## Misconfigurations

### 1. No response model / returning ORM objects directly

**What:** Returning a SQLAlchemy/Pydantic model without a response model leaks fields the caller shouldn't see (`password_hash`, `role`, internal IDs).

**Dangerous pattern:**
```python
@app.get("/users/{id}")
def get_user(id): return db_user  # full ORM object
```

**Fix:** Declare a response model with only allowed fields.
```python
@app.get("/users/{id}", response_model=UserOut)
def get_user(id): ...
```

**Detection:** `rg -n "response_model|@app.get" *.py`

---

### 2. Missing/weak dependency validation

**What:** Accepting `dict` or untyped params bypasses Pydantic validation.

**Fix:** Use typed `BaseModel` request bodies and path/query params with constraints (`conint`, `constr`, `Field(...)`).

**Detection:** `rg -n "def .*request|Body\(dict\)|: dict" *.py`

---

### 3. Docs (Swagger/ReDoc) exposed in production

**What:** `/docs` and `/redoc` leak route names, schemas, and enum values.

**Fix:** Disable in prod: `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` or gate by env.

**Detection:** `rg -n "FastAPI\(|docs_url|redoc_url" *.py`

---

### 4. CORS allow-all

**What:** `allow_origins=["*"]` with credentials lets any site call your API with the user's cookies.

**Fix:** Allowlist specific origins; `allow_credentials=True` only with explicit origins.

**Detection:** `rg -n "allow_origins|CORSMiddleware" *.py`

---

### 5. Verbose exception responses

**What:** Unhandled exceptions return FastAPI's default 500 with internal detail in some setups; custom handlers that return `str(e)` leak internals.

**Fix:** Add a global exception handler returning generic messages; log detail.

**Detection:** `rg -n "exception_handler|@app.exception_handler" *.py`

---

## Common Vulnerabilities

### 6. BOLA / IDOR

**What:** `user_id` from path used without ownership check.

**Fix:** Verify `resource.owner_id == current_user.id`; prefer UUIDs.

**Detection:** `rg -n "@app.get\(.*\{.*id\}|path_id|item_id" *.py`

---

### 7. SQL injection via raw SQL / f-strings

**What:** `session.execute(f"... WHERE id = {id}")` is SQLi.

**Fix:** Use ORM or bound params: `session.execute(text("... WHERE id = :id"), {"id": id})`.

**Detection:** `rg -n "execute\(f\"|execute\(f'|text\(f\"" *.py`

---

### 8. Mass assignment via `model_dump` / `**body`

**What:** `User(**body.model_dump())` overwrites privileged fields.

**Fix:** Allowlist fields; use separate input/output schemas.

**Detection:** `rg -n "\*\*.*model_dump|\*\*body" *.py`

---

### 9. Insecure deserialization / `eval`

**What:** `pickle.loads` / `eval` on untrusted data → RCE.

**Fix:** Use `json`; never `eval`/`pickle` untrusted input.

**Detection:** `rg -n "pickle\.loads|eval\(|yaml\.load\(" *.py`

---

### 10. SSRF via `httpx`/`requests`

**What:** Outbound HTTP to user URLs hits internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "httpx\..*\(.*url|requests\.get\(.*url" *.py`

---

### 11. ReDoS on validation regexes

**What:** Catastrophic-backtracking `Field(pattern=...)` on user input.

**Fix:** Test regexes with `re2`/`safe-regex`; avoid nested quantifiers.

**Detection:** `rg -n "pattern=|regex=" *.py`

---

### 12. Async blocking the event loop

**What:** Sync CPU/IO in `async def` endpoints blocks all requests.

**Fix:** Offload to `run_in_executor` or use async drivers.

**Detection:** review `async def` endpoints for sync `requests`, `time.sleep`, `open()`.

---

## Checklist

- [ ] Response models declared on every endpoint
- [ ] Typed Pydantic request bodies with constraints
- [ ] Docs disabled in prod
- [ ] CORS allowlist explicit
- [ ] Global exception handler, generic messages
- [ ] Object-level authorization on `:id` routes
- [ ] Parameterized SQL / ORM
- [ ] No mass assignment
- [ ] No `pickle`/`eval`/unsafe `yaml.load`
- [ ] Outbound HTTP allowlisted
- [ ] Regexes safe
- [ ] No sync work in async endpoints

## Quick detection bundle

```bash
rg -n "response_model|@app.get" *.py
rg -n "FastAPI\(|docs_url|redoc_url" *.py
rg -n "allow_origins|CORSMiddleware" *.py
rg -n "execute\(f\"|execute\(f'|text\(f\"" *.py
rg -n "pickle\.loads|eval\(|yaml\.load\(" *.py
rg -n "httpx\..*\(.*url|requests\.get\(.*url" *.py
```
