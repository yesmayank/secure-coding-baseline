# Node.js + Express — Misconfigurations & Common Vulnerabilities

Defensive reference for Node.js HTTP services using Express. Each section: what it is, dangerous pattern, what leaks, fix, detection.

---

## Misconfigurations

### 1. Over-broad `express.static`

**What:** Serving files from the project root or a parent directory exposes source, config, and secrets over HTTP.

**Dangerous pattern:**
```js
app.use(express.static(__dirname));
app.use(express.static('.'));
```

**Leaks:** `package.json`, `.env`, `*.json` credentials, all `.js` source, `node_modules/`, `.git/`.

**Fix:** Serve only a dedicated public dir.
```js
app.use('/static', express.static(path.join(__dirname, 'public')));
```

**Detection:** `rg -n "express\.static\(" app/`

---

### 2. Path traversal in file reads

**What:** `fs.readFile` / `fs.createReadStream` / `res.sendFile` fed user input without bounds-checking lets `../` escape the intended directory.

**Dangerous pattern:**
```js
const filePath = path.join(__dirname + '/templates', req.params.name);
res.sendFile(filePath);
```
`path.join` does **not** sanitize `../`.

**Leaks:** Any file readable by the process UID — source, `.env`, `/etc/passwd`, sibling credential files.

**Fix:** Resolve against a fixed base and verify the result stays inside it.
```js
const BASE = path.resolve(__dirname, 'templates');
const target = path.resolve(BASE, req.params.name);
if (target !== BASE && !target.startsWith(BASE + path.sep)) {
  return res.status(400).send('Invalid path');
}
```

**Detection:** `rg -n "fs\.(readFile|createReadStream|readFileSync)|res\.sendFile" app/` and `rg -n "path\.join\([^)]*req\." app/`

---

### 3. Verbose error responses in production

**What:** Sending `err.stack` or raw `err` to the client leaks absolute paths and code context.

**Dangerous pattern:**
```js
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
  res.status(500).json({ error: err });
});
```

**Leaks:** Stack traces like `at /app/server.js:47:12` — a map of your source layout and container paths.

**Fix:** Run `NODE_ENV=production`; log detail server-side, send generic message.
```js
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'internal_error' });
});
```

**Detection:** `rg -n "res\.send\(err|res\.send\(.*\.stack|res\.json\(\{ ?error: ?err" app/`

---

### 4. Catch-all routes that reflect input

**What:** A fallback handler echoing `req.url` or `req.body` leaks internal structure and enables XSS.

**Dangerous pattern:**
```js
app.use('*', (req, res) => {
  res.send(`Not found: ${req.url}`);
});
```

**Fix:** Return a static 404 body; never reflect raw request data.

**Detection:** `rg -n "app\.use\('\*'" app/`

---

### 5. Source maps and dev artifacts shipped to prod

**What:** `.map`, `node_modules/`, `.git/`, `coverage/` in the image let attackers reconstruct source or browse history.

**Fix:** Disable source maps in prod or send them only to a private error backend (Sentry). Use a `.dockerignore` excluding `.git`, `node_modules`, `coverage`, `*.map`, `.env*`.

**Detection:** `find . -name "*.map" -not -path "./node_modules/*"`; inspect `.dockerignore`.

---

### 6. Body parser without limits

**What:** `bodyParser.json()` with no `limit` allows memory/CPU exhaustion; reflection of parsed bodies is an XSS/leak vector.

**Dangerous pattern:**
```js
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
```

**Fix:**
```js
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));
```

**Detection:** `rg -n "bodyParser\.json\(\)|bodyParser\.urlencoded\(" app/`

---

### 7. Missing security headers

**What:** Without `helmet`, Express advertises `X-Powered-By` and omits `X-Content-Type-Options`, CSP, HSTS.

**Fix:**
```js
const helmet = require('helmet');
app.use(helmet());
app.disable('x-powered-by');
```

**Detection:** `rg -n "helmet" app/package.json`

---

### 8. Secrets committed to the repo

**What:** Credentials in git leak at the repo layer regardless of server config.

**Leaks:** Firebase/GCP service account keys, `keys.json`, `google_creds.json`, `.env`.

**Fix:** Rotate all committed credentials; move to K8s secrets / env / secret manager; add to `.gitignore`; scrub history with `git filter-repo` / BFG if pushed.

**Detection:** `git ls-files | rg -i "creds|keys|adminsdk|\.env$|firebase"`

---

## Common Vulnerabilities

### 9. Prototype pollution

**What:** Merging user-controlled objects (`Object.assign` into a target, `lodash.merge` of untrusted data, `qs` extended parsing) can pollute `Object.prototype` and alter behavior of unrelated code.

**Dangerous pattern:**
```js
const cfg = Object.assign({}, req.body); // if body contains __proto__
```

**Fix:** Reject `__proto__` and `constructor` keys; use `Object.create(null)`; keep `qs` and `lodash` patched; avoid `bodyParser.urlencoded({ extended: true })` unless needed.

**Detection:** `rg -n "Object\.assign|lodash\.merge|\.merge\(" app/`

---

### 10. Command injection

**What:** `child_process.exec` with user input runs arbitrary shell commands.

**Dangerous pattern:**
```js
exec(`convert ${req.file.originalname} out.png`);
```

**Fix:** Use `execFile`/`spawn` with arg arrays (no shell), validate input, never interpolate into a command string.

**Detection:** `rg -n "exec\(|execSync\(|spawn\(.*shell" app/`

---

### 11. ReDoS (regular expression denial of service)

**What:** Catastrophic-backtracking regexes on user input hang the event loop.

**Fix:** Use `safe-regex` / `re2`; avoid nested quantifiers `(a+)+`; set timeouts for external regex.

**Detection:** `rg -n "new RegExp\(" app/`

---

### 12. SSRF via outbound HTTP

**What:** `axios`/`fetch` to user-supplied URLs can hit internal metadata endpoints (`169.254.169.254`).

**Fix:** Allowlist outbound hosts; block link-local and RFC1918 ranges; validate URL schemes.

**Detection:** `rg -n "axios\.(get|post)\(.*req\.|fetch\(.*req\." app/`

---

### 13. Insecure deserialization

**What:** `JSON.parse` of untrusted data is usually fine, but `node-serialize` / `funcster` / custom revivers enable RCE.

**Fix:** Avoid `node-serialize.unserialize` on untrusted input entirely.

**Detection:** `rg -n "node-serialize|\.unserialize\(" app/`

---

## Checklist

- [ ] No `express.static` on root/parent dirs
- [ ] All user-influenced file paths bounds-checked
- [ ] `NODE_ENV=production`; no stack traces to clients
- [ ] Catch-all routes return static 404
- [ ] `.dockerignore` excludes `.git`, `node_modules`, `.env*`, `*.map`
- [ ] `bodyParser` limits set
- [ ] `helmet` enabled; `x-powered-by` disabled
- [ ] No committed credentials (rotate + gitignore + scrub history)
- [ ] No `eval`/`exec` on user input
- [ ] Outbound HTTP allowlisted (SSRF)
- [ ] Dependencies patched (`npm audit`)

## Quick detection bundle

```bash
rg -n "express\.static\(" app/
rg -n "fs\.(readFile|createReadStream|readFileSync)|res\.sendFile" app/
rg -n "path\.join\([^)]*req\." app/
rg -n "res\.send\(err|res\.send\(.*\.stack|res\.json\(\{ ?error: ?err" app/
rg -n "eval\(|exec\(|execSync\(|spawn\(.*shell" app/
rg -n "bodyParser\.json\(\)|bodyParser\.urlencoded\(" app/
rg -n "helmet" app/package.json
git ls-files | rg -i "creds|keys|adminsdk|\.env$|firebase"
```
