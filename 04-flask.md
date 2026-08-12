# Python + Flask — Misconfigurations & Common Vulnerabilities

Defensive reference for Flask web services.

---

## Misconfigurations

### 1. `debug=True` in production

**What:** Flask's debugger renders the interactive Werkzeug console on exceptions — full RCE if reachable, plus stack traces and source.

**Dangerous pattern:**
```python
app.run(debug=True)
```

**Leaks:** Source, local vars, and (with the debugger PIN) arbitrary code execution.

**Fix:** `app.run(debug=False)` in prod; use `gunicorn`/`uwsgi`; never expose the debugger.

**Detection:** `rg -n "debug\s*=\s*True|app\.run\(" *.py`

---

### 2. `SECRET_KEY` hardcoded or default

**What:** Flask signs sessions with `SECRET_KEY`. A hardcoded/weak key lets attackers forge session cookies.

**Dangerous pattern:**
```python
app.secret_key = "dev"
```

**Fix:** Load from env; rotate if leaked.

**Detection:** `rg -n "secret_key|SECRET_KEY" *.py`

---

### 3. Static folder served from project root

**What:** `Flask(__name__)` serves `static/` by default; pointing `static_folder` at `.` or `__name__`'s parent exposes source.

**Fix:** Keep `static_folder='static'`; never set it to `.` or a parent.

**Detection:** `rg -n "static_folder|Flask\(__name__\)" *.py`

---

### 4. `send_file` / `send_from_directory` with user input

**What:** `send_file(request.args['f'])` reads arbitrary files.

**Dangerous pattern:**
```python
return send_file(os.path.join(UPLOADS, request.args['f']))
```

**Fix:** Use `send_from_directory(base, filename)` and validate `filename` has no path separators; resolve and bounds-check.

**Detection:** `rg -n "send_file|send_from_directory" *.py`

---

### 5. Verbose error pages

**What:** Default HTML error pages with `debug=True` leak stack traces.

**Fix:** Register error handlers returning generic messages; log server-side.

**Detection:** `rg -n "errorhandler|abort\(" *.py`

---

## Common Vulnerabilities

### 6. SSTI via Jinja2 with user templates

**What:** `render_template_string(user_input)` renders user content as a template → RCE via `{{ config }}`, `{{ ''.__class__ }}`.

**Dangerous pattern:**
```python
return render_template_string(f"Hello {name}")
```

**Fix:** Never render user input as a template. Pass as a variable: `render_template_string("Hello {{ name }}", name=name)`.

**Detection:** `rg -n "render_template_string" *.py`

---

### 7. SQL injection via f-strings

**What:** `db.execute(f"... WHERE id = {id}")` is classic SQLi.

**Fix:** Use parameterized queries: `db.execute("... WHERE id = ?", (id,))` or an ORM (SQLAlchemy).

**Detection:** `rg -n "execute\(f\"|execute\(f'|\.execute\(.*\+" *.py`

---

### 8. Mass assignment / unsafe `**request.json`

**What:** `Model(**request.json)` lets attackers set privileged fields.

**Fix:** Allowlist fields explicitly.

**Detection:** `rg -n "\*\*request\.json|\*\*request\.form" *.py`

---

### 9. Missing CSRF on forms

**What:** Flask has no built-in CSRF; forgetting `Flask-WTF` CSRFProtect leaves state-changing routes open.

**Fix:** Enable `CSRFProtect(app)` for session-based forms; use tokens for APIs.

**Detection:** `rg -n "CSRFProtect|flask_wtf" *.py`

---

### 10. Insecure deserialization

**What:** `pickle.loads` / `yaml.load` (unsafe) / `eval` on untrusted data → RCE.

**Fix:** Use `json`; `yaml.safe_load`.

**Detection:** `rg -n "pickle\.loads|yaml\.load\(|eval\(" *.py`

---

### 11. Path traversal

**What:** `open(os.path.join(BASE, path))` with user `path` containing `..`.

**Fix:** Resolve and prefix-check against `BASE`.

**Detection:** `rg -n "os\.path\.join\(.*request|open\(.*request" *.py`

---

### 12. SSRF via `requests.get(user_url)`

**What:** Outbound HTTP to user URLs reaches internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "requests\.get\(.*request|urlopen\(.*request" *.py`

---

## Checklist

- [ ] `debug=False` in prod; no debugger reachable
- [ ] `SECRET_KEY` from env; rotated if leaked
- [ ] `static_folder` scoped to `static/`
- [ ] `send_from_directory` with validated filenames
- [ ] Error handlers generic; no stack traces to client
- [ ] No `render_template_string` with user input
- [ ] Parameterized SQL
- [ ] Allowlist fields on model construction
- [ ] CSRF protection enabled
- [ ] No `pickle`/`eval`/unsafe `yaml.load`
- [ ] File paths bounds-checked
- [ ] Outbound HTTP allowlisted

## Quick detection bundle

```bash
rg -n "debug\s*=\s*True|app\.run\(" *.py
rg -n "secret_key|SECRET_KEY" *.py
rg -n "send_file|send_from_directory" *.py
rg -n "render_template_string" *.py
rg -n "execute\(f\"|execute\(f'|\.execute\(.*\+" *.py
rg -n "pickle\.loads|yaml\.load\(|eval\(" *.py
rg -n "requests\.get\(.*request|urlopen\(.*request" *.py
```
