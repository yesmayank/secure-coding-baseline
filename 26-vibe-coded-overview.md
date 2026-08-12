# Vibe-Coded Applications — Overview of Common Vulnerabilities

Defensive reference for security issues that recur in applications built primarily by AI coding assistants ("vibe coding"). These bugs share a root cause: the assistant optimizes for the happy path and plausible-looking code, while skipping the adversarial checks an experienced engineer would add by habit.

---

## Why vibe-coded apps have a distinct risk profile

AI-generated code tends to be correct *in shape* but weak *in posture*. Patterns observed across reported incidents:

- **Happy-path bias:** the generated function works for valid input and never considers what an attacker sends.
- **Plausible defaults:** frameworks' least-secure defaults are accepted silently (CORS `*`, `debug=True`, `trust all`, `allowAllOrigins`).
- **Invented facts:** nonexistent packages, deprecated APIs, and fabricated function signatures that look real ("hallucinated" dependencies and methods).
- **Secrets in source:** API keys, tokens, and connection strings pasted into code "to make it work," then committed.
- **Copy-paste of insecure snippets:** `eval`, `exec`, string-concatenated SQL, `dangerouslySetInnerHTML`, `v-html` — repeated across files.
- **Missing authz, not authn:** login is generated, but object-level authorization (`user 17 can read user 18's record`) is usually absent.
- **Test/debug scaffolding shipped:** `console.log` of secrets, `/debug` routes, `APP_DEBUG=true`, sample credentials left in.

The rest of this section is split into focused docs:

- [27 — Secrets & supply chain](./27-vibe-coded-secrets-supplychain.md)
- [28 — Authentication & authorization](./28-vibe-coded-auth-authz.md)
- [29 — Injection & input validation](./29-vibe-coded-injection-validation.md)
- [30 — Configuration & deployment](./30-vibe-coded-config-deployment.md)

---

## Top recurring vulnerability classes (summary index)

| # | Class | Why AI generates it | Doc |
|---|-------|-------------------|-----|
| 1 | Hardcoded secrets | Pasted "to make it work" | 27 |
| 2 | Hallucinated / typosquat packages | Invented imports | 27 |
| 3 | Outdated vulnerable deps | Whatever was in training data | 27 |
| 4 | Weak / fake auth | Login stubs that "look right" | 28 |
| 5 | Missing object-level authz (BOLA/IDOR) | Happy-path only | 28 |
| 6 | Mass assignment | `Model(**body)` convenience | 28 |
| 7 | JWT in localStorage / weak signing | Common blog snippets | 28 |
| 8 | Missing rate limiting | Not in the prompt | 28 |
| 9 | SQL injection | String-concatenated queries | 29 |
| 10 | NoSQL injection | Spread `req.body` into queries | 29 |
| 11 | Command injection | `exec`/backticks with input | 29 |
| 12 | XSS | `v-html`/`dangerouslySetInnerHTML`/`{!! !!}` | 29 |
| 13 | SSTI | `render_template_string(user_input)` | 29 |
| 14 | Path traversal / LFI | `include`/`open` with user path | 29 |
| 15 | SSRF | `fetch(user_url)` / `requests.get(url)` | 29 |
| 16 | Insecure deserialization | `pickle`/`unserialize`/`Marshal` | 29 |
| 17 | Prototype pollution | `Object.assign`/`merge` of body | 29 |
| 18 | Verbose errors / debug mode | Defaults left on | 30 |
| 19 | Permissive CORS | `*` with credentials | 30 |
| 20 | CSRF disabled/excluded | "to make the form work" | 30 |
| 21 | Open redirect | `redirect(next)` convenience | 30 |
| 22 | Insecure file upload | Accept anything, store in webroot | 30 |
| 23 | Debug/test routes shipped | `/test`, `/eval`, sample data | 30 |
| 24 | Weak crypto / hardcoded salts | `md5`, `rand()`, `"salt"` | 30 |
| 25 | No security headers / helmet | Not requested | 30 |

---

## How to use these docs

- Run the detection greps in your generated codebase.
- Treat every AI-generated commit as unreviewed until checked against the relevant doc.
- Add the checks to CI (e.g., `gitleaks`, `semgrep`, `npm audit`, `pip-audit`, `trivy`).
- Add a review step that specifically looks for the classes above — they are the ones most likely to slip past a quick "looks fine" approval.

---

## Review prompt for AI-generated code

A short checklist to paste when reviewing vibe-coded PRs:

```
Review this diff for the following AI-generated-code failure modes and report each finding with file:line:
1. Hardcoded secrets, keys, tokens, connection strings
2. Invented/typosquat package names or deprecated APIs
3. Login that doesn't verify passwords / sessions that aren't scoped
4. Missing object-level authorization on :id routes (BOLA/IDOR)
5. Mass assignment (binding raw body to a model)
6. SQL/NoSQL/command injection (string concat, $where, exec with input)
7. XSS (v-html, dangerouslySetInnerHTML, {!! !!}, Html.Raw, raw)
8. SSTI (render_template_string with user input)
9. Path traversal / LFI (include/open with user path)
10. SSRF (fetch/requests to user-supplied URL)
11. Insecure deserialization (pickle/unserialize/Marshal/yaml.load)
12. Prototype pollution (Object.assign/merge of request body)
13. Debug mode, verbose errors, /debug or /test routes
14. Permissive CORS, CSRF disabled, open redirect
15. Insecure file upload (any type, stored in webroot)
16. Weak crypto (md5/sha1, rand(), hardcoded salt)
17. Missing security headers / no helmet
18. No rate limiting on auth
```

---

## Checklist (cross-cutting)

- [ ] No secrets in source (scan with `gitleaks`)
- [ ] All imports resolve to real, non-typosquat packages (`npm ls`/`pip-audit`)
- [ ] Dependencies pinned and scanned
- [ ] Every `:id` route has object-level authz
- [ ] No raw body bound to models
- [ ] All queries parameterized
- [ ] No `eval`/`exec`/shell with user input
- [ ] No unescaped HTML output
- [ ] No `include`/`open` of user paths
- [ ] Outbound HTTP allowlisted
- [ ] No `pickle`/`unserialize`/`Marshal`/unsafe `yaml.load`
- [ ] Debug off; no debug routes; generic errors
- [ ] CORS allowlist; CSRF on; redirects allowlisted
- [ ] File uploads allowlisted + validated + stored outside webroot
- [ ] bcrypt/argon2 + CSPRNG tokens
- [ ] Security headers on; rate limiting on auth
