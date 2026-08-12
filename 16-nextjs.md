# Next.js — Misconfigurations & Common Vulnerabilities

Defensive reference for Next.js apps (App Router & Pages Router).

---

## Misconfigurations

### 1. Secrets in client components / `NEXT_PUBLIC_`

**What:** Any `NEXT_PUBLIC_*` env var is inlined into the client bundle and visible in browser source. Putting API keys there leaks them.

**Fix:** Keep secrets server-side only (no `NEXT_PUBLIC_` prefix); access in server components / API routes / route handlers only.

**Detection:** `rg -n "NEXT_PUBLIC_" .env*`; review usage of `NEXT_PUBLIC_` for actual secrets.

---

### 2. Exposed API routes / route handlers without auth

**What:** `app/api/*` or `pages/api/*` with no auth check are public endpoints.

**Fix:** Add auth middleware or per-route checks; default-deny.

**Detection:** `rg -n "export (async )?function (GET|POST)|export default function handler" app/ pages/`

---

### 3. `getServerSideProps` returning sensitive data to client

**What:** Passing full DB rows to `props` serializes everything into the page HTML.

**Fix:** Select only needed fields; never pass `password_hash`, tokens, or PII to client props.

**Detection:** `rg -n "getServerSideProps|return { props" pages/`

---

### 4. `dangerouslySetInnerHTML` without sanitization

**What:** `<div dangerouslySetInnerHTML={{__html: data}} />` on untrusted data → XSS.

**Fix:** Sanitize with DOMPurify server-side; prefer structured rendering.

**Detection:** `rg -n "dangerouslySetInnerHTML" app/ pages/ components/`

---

### 5. Source maps shipped to prod

**What:** `productionBrowserSourceMaps: true` (or default in some setups) publishes original source via `.map`.

**Fix:** Disable browser source maps in prod or upload only to a private error backend (Sentry).

**Detection:** `rg -n "productionBrowserSourceMaps|sourceMap" next.config.*`

---

### 6. Middleware running on everything / SSRF in rewrites

**What:** `rewrites()` proxying to user-influenced destinations → SSRF; middleware with heavy logic on all routes → DoS.

**Fix:** Avoid dynamic rewrite targets; scope middleware with a matcher.

**Detection:** `rg -n "rewrites\(|destination|matcher" next.config.* middleware.*`

---

## Common Vulnerabilities

### 7. SSRF via `fetch` in server components / route handlers

**What:** Server-side `fetch(userUrl)` hits internal metadata (`169.254.169.254`).

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "fetch\(.*req\.|fetch\(.*params\.|fetch\(.*query\." app/ pages/`

---

### 8. Open redirect in `redirect()` / `next/navigation`

**What:** `redirect(req.nextUrl.searchParams.get('next'))` to attacker site.

**Fix:** Allowlist local targets.

**Detection:** `rg -n "redirect\(|res.redirect\(" app/ pages/`

---

### 9. CSRF on server actions / mutations

**What:** Server Actions without CSRF protection (Next.js has built-in origin checks; disabling them or using raw POST routes removes protection).

**Fix:** Keep `allowDevelopmentOrigin`/origin checks enabled; verify `Origin` on mutations; use signed cookies.

**Detection:** `rg -n "use server|export async function.*Action" app/`

---

### 10. Mass assignment in API routes

**What:** `db.user.create({ data: req.body })` with full body.

**Fix:** Pick allowed fields explicitly.

**Detection:** `rg -n "req\.body|data:.*body" app/api pages/api`

---

### 11. SQL injection in route handlers

**What:** `query("... WHERE id = " + req.query.id)`.

**Fix:** Parameterized queries / ORM.

**Detection:** `rg -n "query\(.*\+|execute\(.*\+|raw\(.*\+" app/ pages/`

---

### 12. Cache poisoning via headers

**What:** Caching pages keyed on unvalidated headers (`x-forwarded-host`) leads to stored poisoning.

**Fix:** Validate/sanitize headers before using in cache keys or links.

**Detection:** `rg -n "headers\(\)|x-forwarded|unstable_cache|revalidate" app/`

---

## Checklist

- [ ] No secrets under `NEXT_PUBLIC_`
- [ ] All API routes / route handlers authenticated
- [ ] Server-side data trimmed before reaching client props
- [ ] No `dangerouslySetInnerHTML` without sanitization
- [ ] Browser source maps disabled in prod
- [ ] Rewrites static; middleware scoped with matcher
- [ ] Outbound `fetch` allowlisted (SSRF)
- [ ] Redirect targets allowlisted
- [ ] Origin checks on mutations
- [ ] Explicit field selection on writes
- [ ] Parameterized SQL
- [ ] Cache keys not derived from unvalidated headers

## Quick detection bundle

```bash
rg -n "NEXT_PUBLIC_" .env*
rg -n "dangerouslySetInnerHTML" app/ pages/ components/
rg -n "productionBrowserSourceMaps" next.config.*
rg -n "rewrites\(|destination|matcher" next.config.* middleware.*
rg -n "fetch\(.*req\.|fetch\(.*params\." app/ pages/
rg -n "redirect\(|res\.redirect\(" app/ pages/
rg -n "query\(.*\+|execute\(.*\+" app/ pages/
```
