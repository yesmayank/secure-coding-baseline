# Angular — Misconfigurations & Common Vulnerabilities

Defensive reference for Angular apps.

---

## Misconfigurations

### 1. Secrets bundled into client (`environment.ts`)

**What:** API keys, third-party secrets placed in `environment.ts` are shipped to the browser.

**Fix:** Keep secrets server-side; proxy through a backend; use short-lived tokens.

**Detection:** `rg -n "apiKey|secret|token" src/environments/`

---

### 2. `bypassSecurityTrustHtml` / `innerHTML` without sanitization

**What:** Angular sanitizes `[innerHTML]` by default, but `DomSanitizer.bypassSecurityTrustHtml` disables it → XSS.

**Fix:** Avoid bypass; if required, sanitize with DOMPurify first.

**Detection:** `rg -n "bypassSecurityTrust|innerHTML" src/`

---

### 3. `DomSanitizer.bypassSecurityTrustUrl` on user URLs

**What:** Trusting user URLs enables `javascript:` URLs in links/iframe src.

**Fix:** Validate scheme (`http`/`https`) before trusting.

**Detection:** `rg -n "bypassSecurityTrustUrl|bypassSecurityTrustResourceUrl" src/`

---

### 4. Weak CSP / `unsafe-inline` / `unsafe-eval`

**What:** Angular requires either nonce-based CSP or `unsafe-inline`; adding `unsafe-eval` weakens it.

**Fix:** Use nonce-based CSP; remove `unsafe-eval`; ensure `Angular` production build (no JIT eval).

**Detection:** check CSP headers / `index.html`.

---

### 5. Source maps shipped to prod

**What:** `ng build --source-map` (or `sourceMap: true` in prod config) publishes original TS source.

**Fix:** Disable source maps in prod or upload to private error backend.

**Detection:** `rg -n "sourceMap" angular.json`

---

## Common Vulnerabilities

### 6. JWT in `localStorage`

**What:** Exfiltratable by XSS.

**Fix:** httpOnly, Secure, SameSite cookie + short-lived tokens.

**Detection:** `rg -n "localStorage\.setItem.*token|sessionStorage" src/`

---

### 7. Open redirect via `Router` / `window.location`

**What:** `this.router.navigateByUrl(queryReturn)` to attacker site.

**Fix:** Allowlist local routes.

**Detection:** `rg -n "navigateByUrl|navigate\(|window\.location" src/`

---

### 8. CSRF / XSRF token misconfigured

**What:** HttpClient XSRF protection disabled or cookie names mismatched.

**Fix:** Enable `HttpClientXsrfModule`/built-in XSRF; ensure backend validates the header.

**Detection:** `rg -n "XSRF|Csrf|withXSRF" src/`

---

### 9. Unvalidated route guards

**What:** Routes without `canActivate` guards render privileged views.

**Fix:** Apply `authGuard`/`canActivate` to protected routes; default-deny.

**Detection:** `rg -n "canActivate|canMatch|AuthGuard" src/`

---

### 10. PostMessage without origin validation

**What:** `window.addEventListener('message')` without `e.origin` check.

**Fix:** Validate origin; use `targetOrigin` on send.

**Detection:** `rg -n "addEventListener\('message'|addEventListener\(\"message\"" src/`

---

### 11. Prototype pollution via `Object.assign` / `merge`

**What:** Merging untrusted JSON into objects.

**Fix:** Use `Object.create(null)`; reject `__proto__`/`constructor`.

**Detection:** `rg -n "Object\.assign|merge\(" src/`

---

### 12. Reverse tabnabbing (`target="_blank"` without `rel`)

**What:** New tabs can access `window.opener`.

**Fix:** `rel="noopener noreferrer"`.

**Detection:** `rg -n "target=\"_blank\"|target='_blank'" src/`

---

## Checklist

- [ ] No secrets in `environment.ts`
- [ ] No `bypassSecurityTrust*` without sanitization
- [ ] User URLs scheme-validated
- [ ] Nonce-based CSP; no `unsafe-eval`
- [ ] Source maps disabled in prod
- [ ] Tokens in httpOnly cookies
- [ ] Redirect targets allowlisted
- [ ] XSRF protection enabled and validated server-side
- [ ] Route guards on protected routes
- [ ] `message` origin validated
- [ ] No prototype pollution via unsafe merges
- [ ] `rel="noopener noreferrer"` on external links

## Quick detection bundle

```bash
rg -n "apiKey|secret|token" src/environments/
rg -n "bypassSecurityTrust|innerHTML" src/
rg -n "localStorage\.setItem.*token" src/
rg -n "navigateByUrl|navigate\(|window\.location" src/
rg -n "XSRF|Csrf|withXSRF" src/
rg -n "canActivate|canMatch|AuthGuard" src/
rg -n "addEventListener\('message'" src/
rg -n "target=\"_blank\"" src/
```
