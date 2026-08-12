# React (SPA) — Misconfigurations & Common Vulnerabilities

Defensive reference for client-side React single-page apps.

---

## Misconfigurations

### 1. Secrets bundled into client code

**What:** `REACT_APP_*` / Vite `VITE_*` env vars and any imported key are inlined into the JS bundle and readable in browser source/devtools.

**Fix:** Never ship API keys, third-party secrets, or DB credentials to the client. Proxy through your backend; use short-lived tokens issued by your server.

**Detection:** `rg -n "REACT_APP_|VITE_" .env*`; review any `apiKey`/`secret` imports in `src/`.

---

### 2. `dangerouslySetInnerHTML` without sanitization

**What:** Rendering untrusted HTML/markdown → XSS.

**Fix:** Sanitize with DOMPurify before setting; prefer structured children.

**Detection:** `rg -n "dangerouslySetInnerHTML" src/`

---

### 3. JWT in `localStorage` / `sessionStorage`

**What:** Tokens in JS-accessible storage are exfiltratable by any XSS.

**Fix:** Short-lived access token in memory + refresh via httpOnly, Secure, SameSite cookie; or use a backend session.

**Detection:** `rg -n "localStorage\.setItem.*token|sessionStorage\.setItem.*token" src/`

---

### 4. Weak CSP / no CSP

**What:** Without a Content-Security-Policy, injected scripts run freely.

**Fix:** Ship a strict CSP (nonce-based or hash-based for inline scripts); avoid `unsafe-inline`/`unsafe-eval`.

**Detection:** check `index.html` and server headers for `Content-Security-Policy`.

---

### 5. Verbose error/stack rendering in prod

**What:** `ErrorBoundary` rendering `err.stack` to the UI leaks source paths.

**Fix:** Show generic error UI; log to Sentry server-side.

**Detection:** `rg -n "err\.stack|error\.stack|\.stack" src/`

---

## Common Vulnerabilities

### 6. Stored XSS via reflected state

**What:** Rendering user-generated content (names, bios, comments) without escaping context. React escapes text by default, but `href={url}` with `javascript:` URLs, or `style` with user input, bypasses escaping.

**Fix:** Validate URLs (require `http:`/`https:`); sanitize HTML; avoid `style` from raw user input.

**Detection:** `rg -n "href=\{.*\}|src=\{.*\}|style=\{.*\}" src/`

---

### 7. Open redirect in client routing

**What:** `window.location = query.get('next')` to attacker site.

**Fix:** Allowlist local targets; reject absolute URLs.

**Detection:** `rg -n "window\.location|location\.href|location\.assign" src/`

---

### 8. PostMessage without origin validation

**What:** `addEventListener('message', e => ...)` without checking `e.origin` accepts messages from any origin.

**Fix:** Validate `e.origin` against an allowlist; use `targetOrigin` on `postMessage`.

**Detection:** `rg -n "addEventListener\('message'|addEventListener\(\"message\"" src/`

---

### 9. Insecure third-party redirects / SSRF-like client calls

**What:** Fetching user-supplied URLs from the client (less severe, but can leak tokens to third parties via URL params).

**Fix:** Don't put tokens in URL params; validate targets.

**Detection:** `rg -n "fetch\(.*token|fetch\(.*\$\{" src/`

---

### 10. Prototype pollution via `Object.assign`/`merge`

**What:** Merging untrusted JSON into objects can pollute `__proto__`.

**Fix:** Use `Object.create(null)`; reject `__proto__`/`constructor` keys; keep `lodash` patched.

**Detection:** `rg -n "Object\.assign|merge\(|deepmerge" src/`

---

### 11. Overly permissive `target="_blank"` without `rel="noopener"`

**What:** Opens new tabs that can access `window.opener` (reverse tabnabbing).

**Fix:** `rel="noopener noreferrer"`.

**Detection:** `rg -n "target=\"_blank\"|target='_blank'" src/`

---

### 12. Exposing internal routes/state via deep links

**What:** SPA routes that assume auth but render structure/data before client-side auth check completes.

**Fix:** Gate rendering behind auth state; don't ship privileged data in initial bundle.

**Detection:** review route components for data loaded before auth check.

---

## Checklist

- [ ] No secrets in client bundle
- [ ] No `dangerouslySetInnerHTML` without DOMPurify
- [ ] Tokens in httpOnly cookies, not `localStorage`
- [ ] Strict CSP shipped
- [ ] No stack traces rendered to UI
- [ ] User URLs validated (scheme); `href`/`style` sanitized
- [ ] Redirect targets allowlisted
- [ ] `message` origin validated
- [ ] No tokens in URL params
- [ ] No prototype pollution via unsafe merges
- [ ] `rel="noopener noreferrer"` on external links
- [ ] Auth gate before privileged data render

## Quick detection bundle

```bash
rg -n "REACT_APP_|VITE_" .env*
rg -n "dangerouslySetInnerHTML" src/
rg -n "localStorage\.setItem.*token|sessionStorage\.setItem.*token" src/
rg -n "href=\{.*\}|src=\{.*\}|style=\{.*\}" src/
rg -n "window\.location|location\.href" src/
rg -n "addEventListener\('message'|addEventListener\(\"message\"" src/
rg -n "target=\"_blank\"|target='_blank'" src/
```
