# Python + Django — Misconfigurations & Common Vulnerabilities

Defensive reference for Django web services.

---

## Misconfigurations

### 1. `DEBUG = True` in production

**What:** Django's debug page renders full stack traces, local variables, settings, and SQL on any exception — a massive source/config/secret leak.

**Dangerous pattern:**
```python
DEBUG = True
```

**Leaks:** Settings (including `SECRET_KEY`, DB credentials, env-injected API keys), source file paths, local variable values, executed SQL.

**Fix:** `DEBUG = False` in prod; set `ALLOWED_HOSTS`; never rely on env defaults that flip it on.

**Detection:** `rg -n "DEBUG\s*=\s*True" settings.py`

---

### 2. `SECRET_KEY` hardcoded or committed

**What:** The Django secret key signs sessions, CSRF tokens, and password-reset tokens. Leaking it enables session forgery.

**Dangerous pattern:**
```python
SECRET_KEY = "django-insecure-abc123..."
```

**Fix:** Load from env / secret manager; rotate if ever committed.

**Detection:** `rg -n "SECRET_KEY\s*=" settings.py`

---

### 3. Static/media served with directory listing or no auth

**What:** `MEDIA_ROOT` exposed at a public URL with no auth leaks uploaded documents.

**Fix:** Serve media behind auth for private uploads; never put `MEDIA_ROOT` inside a code-served dir; disable directory indexing.

**Detection:** `rg -n "MEDIA_URL|MEDIA_ROOT|STATIC_ROOT" settings.py`

---

### 4. `runserver` used in production

**What:** Running `runserver` in prod leaks the debug page and is single-threaded/unsafe.

**Fix:** Use `gunicorn`/`uwsgi` behind nginx; `runserver` only in dev.

**Detection:** check Dockerfile/Procfile entrypoint for `runserver`.

---

### 5. Exposed `admin` with weak setup

**What:** `/admin/` reachable on the public internet with no rate limit, no 2FA, and default styling is a credential-stuffing magnet.

**Fix:** Move admin to a non-obvious path, restrict to known IP ranges or VPN, enforce 2FA, rate-limit logins.

**Detection:** `rg -n "admin.site.register|urlpatterns.*admin" urls.py`

---

## Common Vulnerabilities

### 6. SQL injection via raw queries

**What:** `raw()`, `extra()`, or `cursor.execute` with string interpolation bypasses parameterization.

**Dangerous pattern:**
```python
Model.objects.raw(f"SELECT * FROM t WHERE name = '{name}'")
cursor.execute(f"SELECT ... WHERE id = {request.GET['id']}")
```

**Fix:** Use the ORM, or `raw()` with params list: `Model.objects.raw("... WHERE id = %s", [id])`.

**Detection:** `rg -n "\.raw\(|\.extra\(|cursor\.execute" */*.py`

---

### 7. Mass assignment via `ModelForm` / `**request.POST`

**What:** Binding request data directly to a model form lets attackers set fields like `is_staff` or `role`.

**Fix:** Use explicit `fields = (...)` in `ModelForm`; never `Model(**request.POST)`.

**Detection:** `rg -n "ModelForm|fields = '__all__'|Model\(\*\*request" */*.py`

---

### 8. BOLA / IDOR on object lookups

**What:** `get_object_or_404(Model, pk=pk)` without ownership checks lets users read others' records.

**Fix:** Filter by owner: `get_object_or_404(Model, pk=pk, owner=request.user)`.

**Detection:** `rg -n "get_object_or_404" */views.py`

---

### 9. CSRF disabled globally

**What:** `csrf_exempt` on a base view or middleware disables protection for sensitive routes.

**Fix:** Keep CSRF on; for APIs use token/JWT auth instead of stripping CSRF.

**Detection:** `rg -n "csrf_exempt|CsrfViewMiddleware.*disabled" */*.py`

---

### 10. Insecure deserialization via `pickle`

**What:** `pickle.loads` on untrusted data is RCE.

**Fix:** Use `json`; never `pickle`/`yaml.load` (unsafe loader) on untrusted input.

**Detection:** `rg -n "pickle\.loads|yaml\.load\(" */*.py`

---

### 11. Path traversal in file serving

**What:** `open(os.path.join(MEDIA_ROOT, filename))` with user-controlled `filename` escapes the dir.

**Fix:** Validate with `os.path.abspath` + prefix check, or use `django.core.files.storage`.

**Detection:** `rg -n "os\.path\.join\(.*request|open\(.*request" */*.py`

---

### 12. Template autoescape disabled

**What:** `{% autoescape off %}` or `mark_safe()` on user input produces XSS.

**Fix:** Keep autoescape on; never `mark_safe` untrusted data.

**Detection:** `rg -n "autoescape off|mark_safe" */templates/ */*.py`

---

## Checklist

- [ ] `DEBUG = False` in prod; `ALLOWED_HOSTS` set
- [ ] `SECRET_KEY` from env; rotated if leaked
- [ ] Private media behind auth; no directory listing
- [ ] `gunicorn`/`uwsgi` in prod, not `runserver`
- [ ] Admin restricted + 2FA + rate limit
- [ ] No raw SQL with interpolation
- [ ] `ModelForm` with explicit `fields`
- [ ] Object lookups scoped by owner
- [ ] CSRF enabled
- [ ] No `pickle`/unsafe `yaml.load` on untrusted input
- [ ] File paths bounds-checked
- [ ] Template autoescape on

## Quick detection bundle

```bash
rg -n "DEBUG\s*=\s*True" settings.py
rg -n "SECRET_KEY\s*=" settings.py
rg -n "\.raw\(|\.extra\(|cursor\.execute" */*.py
rg -n "get_object_or_404" */views.py
rg -n "csrf_exempt" */*.py
rg -n "pickle\.loads|yaml\.load\(" */*.py
rg -n "autoescape off|mark_safe" */templates/ */*.py
```
