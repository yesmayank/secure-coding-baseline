# Vue.js / Nuxt — Misconfigurations & Common Vulnerabilities

Defensive reference for Vue 3 and Nuxt apps.

---

## Misconfigurations

### 1. Secrets in client bundle (`VITE_` / `NUXT_PUBLIC_`)

**What:** Public env vars are inlined into the client bundle and readable in browser source.

**Fix:** Keep secrets server-side; in Nuxt use server routes; never expose keys to the client.

**Detection:** `rg -n "VITE_|NUXT_PUBLIC_|process\.client" .env* nuxt.config.*`

---

### 2. `v-html` without sanitization

**What:** `<div v-html="content" />` renders untrusted HTML → XSS.

**Fix:** Sanitize with DOMPurify before binding; prefer `{{ }}` interpolation.

**Detection:** `rg -n "v-html" src/`

---

### 3. `innerHTML` / `setAttribute` with user input

**What:** Direct DOM manipulation bypasses Vue's escaping.

**Fix:** Avoid; sanitize if unavoidable.

**Detection:** `rg -n "innerHTML|setAttribute\('href'" src/`

---

### 4. Weak CSP / `unsafe-inline` / `unsafe-eval`

**What:** Without nonce-based CSP, inline scripts run; `unsafe-eval` weakens further.

**Fix:** Nonce-based CSP; remove `unsafe-eval`.

**Detection:** check CSP headers / `index.html` / `nuxt.config.*`.

---

### 5. Source maps shipped to prod

**What:** `sourcemap: true` in prod build publishes original source.

**Fix:** Disable in prod or upload to private error backend.

**Detection:** `rg -n "sourcemap|sourceMap" vite.config.* nuxt.config.*`

---

## Common Vulnerabilities

### 6. JWT in `localStorage`

**What:** Exfiltratable by XSS.

**Fix:** httpOnly, Secure, SameSite cookie + short-lived tokens.

**Detection:** `rg -n "localStorage\.setItem.*token|sessionStorage" src/`

---

### 7. Open redirect via `router.push` / `window.location`

**What:** `router.push(query.next)` to attacker site.

**Fix:** Allowlist local routes.

**Detection:** `rg -n "router\.push|router\.replace|window\.location" src/`

---

### 8. CSRF / XSRF misconfigured (Nuxt server routes)

**What:** Nuxt server routes without CSRF protection on mutations.

**Fix:** Enable CSRF token; validate `Origin` on mutations.

**Detection:** `rg -n "csrf|xsrf|sameSite" server/ nuxt.config.*`

---

### 9. Route guards missing

**What:** Protected views rendered before auth check completes.

**Fix:** `beforeEach`/`defineMiddleware` guards; default-deny.

**Detection:** `rg -n "beforeEach|router\.beforeEach|defineNuxtRouteMiddleware|middleware" src/`

---

### 10. PostMessage without origin validation

**What:** `addEventListener('message')` without `e.origin` check.

**Fix:** Validate origin; use `targetOrigin` on send.

**Detection:** `rg -n "addEventListener\('message'|addEventListener\(\"message\"" src/`

---

### 11. SSRF in Nuxt server routes

**What:** `$fetch(userUrl)` in server routes hits internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "\$fetch\(.*req|ofetch\(.*req|useFetch\(.*req" server/`

---

### 12. Reverse tabnabbing

**What:** `target="_blank"` without `rel`.

**Fix:** `rel="noopener noreferrer"`.

**Detection:** `rg -n "target=\"_blank\"|target='_blank'" src/`

---

## Checklist

- [ ] No secrets in client bundle
- [ ] No `v-html`/`innerHTML` without DOMPurify
- [ ] User URLs scheme-validated
- [ ] Nonce-based CSP; no `unsafe-eval`
- [ ] Source maps disabled in prod
- [ ] Tokens in httpOnly cookies
- [ ] Redirect targets allowlisted
- [ ] CSRF on server mutations
- [ ] Route guards on protected views
- [ ] `message` origin validated
- [ ] Outbound `$fetch` allowlisted (SSRF)
- [ ] `rel="noopener noreferrer"` on external links

## Quick detection bundle

```bash
rg -n "VITE_|NUXT_PUBLIC_" .env* nuxt.config.*
rg -n "v-html|innerHTML" src/
rg -n "localStorage\.setItem.*token" src/
rg -n "router\.push|router\.replace|window\.location" src/
rg -n "csrf|xsrf" server/ nuxt.config.*
rg -n "addEventListener\('message'" src/
rg -n "\$fetch\(.*req|ofetch\(.*req" server/
rg -n "target=\"_blank\"" src/
```
