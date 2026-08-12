# Vibe-Coded Apps — Configuration & Deployment

Defensive reference for configuration and deployment failures that recur in AI-generated code. These are the bugs that pass local review because "it works on my machine" — and then leak in production.

---

## 1. Debug mode left on

### What it is
AI defaults to the framework's most verbose setting so the example "just runs." It rarely flips these off for production.

### Dangerous patterns
```js
app.run(debug=True)                          // Flask → interactive debugger
```
```python
DEBUG = True                                 // Django → full debug page
APP_DEBUG=true                               // Laravel → stack traces + env
```
```csharp
ASPNETCORE_ENVIRONMENT=Development           // → UseDeveloperExceptionPage
```
```go
pprof registered on the public mux           // → heap/goroutine/source leak
```

### What leaks
Stack traces with absolute paths, local variables (including secrets), executed SQL, env/config values, and (Flask) interactive code execution.

### Fix
- `NODE_ENV=production`, `DEBUG=False`, `APP_DEBUG=false`, `ASPNETCORE_ENVIRONMENT=Production`.
- Disable `UseDeveloperExceptionPage`/`UseDatabaseErrorPage`; use `UseExceptionHandler`.
- Register pprof/expvar only on an internal listener.

### Detection
```bash
rg -n "debug\s*=\s*True|DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true|UseDeveloperExceptionPage|net/http/pprof|expvar" . --type-add 'cfg:*.{env,conf,yaml,yml,toml,ini,go,py,js,ts,cs}'
```

---

## 2. Permissive CORS

### What it is
"Allow everything so the frontend works" is the AI default.

### Dangerous patterns
```js
app.use(cors({ origin: '*' ', credentials: true }));   // invalid combo, or permissive
```
```python
CORS_ALLOW_ALL_ORIGINS = True
```
```csharp
.AllowAnyOrigin().AllowCredentials()
```

### Fix
- Allowlist explicit origins; `credentials` only with explicit origins (never with `*`).
- Reflect the request origin only against an allowlist.

### Detection
```bash
rg -n "origin:\s*['\"]\*['\"]|allowedOrigins.*\*|AllowAnyOrigin|allow_any|Access-Control-Allow-Origin.*\*" app/ config/
```

---

## 3. CSRF disabled / excluded

### What it is
When a generated form "doesn't work," the assistant often disables CSRF rather than fixing the token flow.

### Dangerous patterns
```js
app.use((req, res, next) => { if (req.headers['x-skip-csrf']) return next(); csrf(req, res, next); });
```
```python
@csrf_exempt
```
```php
protected $except = ['*'];
```

### Fix
- Keep CSRF on for session/cookie auth; for APIs use token auth (Authorization header) which doesn't need CSRF.
- Exclude only stateless webhooks with signature verification.

### Detection
```bash
rg -n "csrf_exempt|CsrfViewMiddleware.*disabled|csrf\(\)\.disable|VerifyCsrfToken.*except|skip_csrf|x-skip-csrf" app/
```

---

## 4. Open redirect

### What it is
`redirect(next)` is the AI default for "where do I go after login."

### Dangerous patterns
```js
res.redirect(req.query.next);
return redirect(request.args.get('next'));
```
```python
return redirect(request.args.get('next'))
```
```ruby
redirect_to(params[:return_to])
```
```csharp
return Redirect(returnUrl);
```

### Fix
- Allowlist local targets; reject absolute/external URLs; verify the target starts with `/` and doesn't start with `//`.

### Detection
```bash
rg -n "redirect\(.*next|redirect\(.*return|redirect\(.*req|redirect\(.*request|redirect\(.*params|Redirect\(.*returnUrl|RedirectToRoute\(.*req" app/
```

---

## 5. Insecure file upload

### What it is
"Accept the file, save it, move on" — no type/size limits, stored in the web root, executable.

### Dangerous patterns
```js
const name = req.file.originalname;
await fs.copyFile(req.file.path, path.join(__dirname, 'public', name));
```
```php
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/'.$_FILES['f']['name']);
```

### What leaks / impact
Webshell upload (`.php`/`.phtml`/`.aspx`), traversal via `../` in the name, stored XSS via HTML, DoS via huge files.

### Fix
- Allowlist extensions; verify MIME with `finfo`/`file-type`; cap size; randomize names; store outside the web root; disable script execution in the upload dir; re-encode images.

### Detection
```bash
rg -n "move_uploaded_file|originalname|multer|FormFile|\.save\(|uploads/" app/
```

---

## 6. Debug / test routes shipped

### What it is
AI scaffolds `/test`, `/debug`, `/eval`, `/run`, `/health` (verbose), or sample-data endpoints that never get removed.

### Dangerous patterns
```js
app.get('/eval', (req, res) => { res.json({ result: eval(req.query.q) }); });
app.get('/debug', (req, res) => res.json({ env: process.env, db }));
```

### Fix
- Remove debug/test routes before prod; gate any diagnostic endpoint behind auth and return only operational status.
- Strip sample/seed data routes from prod builds.

### Detection
```bash
rg -n "app\.(get|post)\(['\"]/(debug|test|eval|run|env|config|dump)|@app\.(get|route)\(['\"]/(debug|test|eval)|@GetMapping\(\"/(debug|test|eval)" app/
rg -n "eval\(.*req|exec\(.*req" app/
```

---

## 7. Verbose error responses

### What it is
Returning `err.stack`, `err.message`, or raw exceptions to the client.

### Dangerous patterns
```js
res.status(500).send(err.stack);
res.status(500).json({ error: err });
```
```python
return str(e), 500
```

### Fix
- Log full error server-side; return generic message; in prod set `NODE_ENV=production`, `APP_DEBUG=false`, `show_exceptions :none`.

### Detection
```bash
rg -n "res\.send\(err|res\.send\(.*\.stack|res\.json\(\{ ?error: ?err|return str\(e\)|formatError.*err\.message" app/
```

---

## 8. Missing security headers

### What it is
AI rarely adds `helmet`/headers unless asked.

### Fix
- Add `helmet` (Node), `secure_headers` (Rails), `django-csp-header`, `NWebOptimizer`/CSP middleware, or set headers at the proxy.
- At minimum: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a strict CSP, HSTS, `Referrer-Policy`.

### Detection
```bash
rg -n "helmet|secure_headers|Content-Security-Policy|X-Content-Type-Options|X-Frame-Options" app/ config/
```
Absence is a finding.

---

## 9. No rate limiting / resource limits

### What it is
Endpoints without rate limits, body size limits, or timeouts → DoS and brute force.

### Fix
- Rate-limit auth and expensive endpoints; set body size limits (`express.json({limit})`, `bodyParser`, `client_max_body_size`); set server/proxy timeouts.

### Detection
```bash
rg -n "rate.?limit|limit_req|client_max_body_size|bodyParser.*limit|json\(\{ ?limit|ReadTimeout|WriteTimeout" app/ config/
```

---

## 10. Weak crypto / hardcoded salts

### What it is
AI copies outdated crypto snippets: `md5`, `sha1`, `Math.random`, `rand()`, hardcoded salts, ECB mode.

### Dangerous patterns
```js
const hash = crypto.createHash('md5').update(password).digest('hex');
const token = Math.random().toString(36);
```
```python
hashlib.md5(password).hexdigest()
random.randint(0, 999999)
```
```php
md5($password); mt_rand();
```

### Fix
- Passwords: bcrypt/argon2. Tokens/IDs: `crypto.randomBytes`/`secrets`/`getrandom`/`crypto/rand`/`OsRng`. Symmetric: AES-GCM/ChaCha20-Poly1305, never ECB. Hashing: SHA-2/SHA-3.

### Detection
```bash
rg -n "createHash\('md5'|createHash\('sha1'|Math\.random|md5\(|sha1\(|hashlib\.md5|hashlib\.sha1|mt_rand\(|rand\(\)|random\.randint|thread_rng|StdRng|SmallRng" app/
```

---

## 11. Logging secrets / PII

### What it is
`console.log(req.body)`, `logger.info(req.headers)`, or Sentry captures of full requests leak secrets to log aggregators.

### Fix
- Redact `Authorization`, `Cookie`, `password`, `token`, `secret` before logging.
- Configure Sentry `beforeSend` to scrub; use winston `redact` format.

### Detection
```bash
rg -n "console\.log\(.*req|logger\.(info|debug|error)\(.*req|winston.*req|Sentry.*capture.*req|print\(.*request" app/
```

---

## 12. Insecure deployment defaults

### What it is
Running as root, `--privileged`, exposed DB/Redis, no TLS, default admin passwords.

### Fix
- Non-root container; dropped caps; `--read-only`; TLS everywhere; secrets from secret manager; firewalls on DB/Redis; rotate defaults.

### Detection (cross-ref the Docker/K8s/Nginx docs)
```bash
rg -n "privileged: true|runAsUser: 0|bind 0\.0\.0\.0|listen_addresses\s*=\s*'\*'" .
```

---

## Checklist

- [ ] Debug off in prod; no developer exception pages; pprof internal-only
- [ ] CORS allowlist explicit; no `*` with credentials
- [ ] CSRF on for session auth; minimal exclusions
- [ ] Redirect targets allowlisted
- [ ] File uploads: allowlist + validate + size cap + stored outside webroot
- [ ] No debug/test/eval routes in prod
- [ ] Generic error messages; full errors logged server-side
- [ ] Security headers on (helmet/CSP/HSTS/nosniff)
- [ ] Rate limiting + body size limits + timeouts
- [ ] bcrypt/argon2 + CSPRNG; no md5/sha1/Math.random
- [ ] Logs redact secrets/PII; Sentry `beforeSend` scrub
- [ ] Non-root, no privileged, TLS, firewalls on data stores, defaults rotated

## Quick detection bundle

```bash
rg -n "debug\s*=\s*True|DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true|UseDeveloperExceptionPage|net/http/pprof" .
rg -n "origin:\s*['\"]\*['\"]|AllowAnyOrigin|allow_any|Access-Control-Allow-Origin.*\*" app/ config/
rg -n "csrf_exempt|csrf\(\)\.disable|VerifyCsrfToken.*except" app/
rg -n "redirect\(.*next|redirect\(.*return|redirect\(.*req|Redirect\(.*returnUrl" app/
rg -n "app\.(get|post)\(['\"]/(debug|test|eval|run|env)" app/
rg -n "res\.send\(err|res\.send\(.*\.stack|return str\(e\)" app/
rg -n "createHash\('md5'|Math\.random|md5\(|sha1\(|hashlib\.md5|mt_rand\(|random\.randint" app/
rg -n "console\.log\(.*req|logger\..*\(.*req" app/
```
