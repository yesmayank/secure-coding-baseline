# Java + Spring Security — Misconfigurations & Common Vulnerabilities

Defensive reference for Spring Security configuration (authz, authn, session, CSRF).

---

## Misconfigurations

### 1. `permitAll()` on sensitive routes

**What:** `http.authorizeHttpRequests(a -> a.anyRequest().permitAll())` disables all authz.

**Dangerous pattern:**
```java
http.authorizeHttpRequests(a -> a.anyRequest().permitAll());
```

**Fix:** Default-deny: `anyRequest().authenticated()` and explicitly allow only public paths.

**Detection:** `rg -n "permitAll|anyRequest" src/`

---

### 2. CSRF disabled globally

**What:** `http.csrf().disable()` on session-cookie apps removes CSRF protection on state changes.

**Fix:** Keep CSRF on for browser/session apps; disable only for pure stateless JWT APIs.

**Detection:** `rg -n "csrf\(\)\.disable|csrf\.disable" src/`

---

### 3. Weak/legacy password encoding

**What:** `NoOpPasswordEncoder` or `MD5`/`SHA1` hashing stores passwords in plaintext or weakly.

**Fix:** Use `BCryptPasswordEncoder` (or Argon2) with appropriate cost.

**Detection:** `rg -n "NoOpPasswordEncoder|MD5|SHA1|MessageDigest" src/`

---

### 4. Insecure JWT config

**What:** Hardcoded signing key in code, `none` algorithm accepted, or symmetric key committed.

**Dangerous pattern:**
```java
Jwts.builder().signWith(SignatureAlgorithm.HS256, "secret".getBytes())
```

**Fix:** Load key from secret store; validate `alg` explicitly (reject `none`); use asymmetric keys if shared across services.

**Detection:** `rg -n "Jwts|signWith|HS256|getBytes\(\)" src/`

---

### 5. Session fixation / no session hardening

**What:** Default session config allows fixation; no `changeSessionId` on auth.

**Fix:** `http.sessionManagement(s -> s.sessionFixation(f -> f.changeSessionId()))`; set cookie `HttpOnly`, `Secure`, `SameSite=Strict`.

**Detection:** `rg -n "sessionManagement|changeSessionId|cookieHttpOnly" src/`

---

## Common Vulnerabilities

### 6. Bypassed authorization via method security gap

**What:** Controller-level `@PreAuthorize` but service methods callable directly (e.g., via messaging/other controllers) without authz.

**Fix:** Apply `@PreAuthorize` at the service layer too; enable `@EnableMethodSecurity`.

**Detection:** `rg -n "@PreAuthorize|@PostAuthorize|@EnableMethodSecurity" src/`

---

### 7. Authority/role escalation via `hasRole` misuse

**What:** `hasRole("USER")` vs `hasAuthority("ROLE_USER")` confusion; granting based on user-supplied field.

**Fix:** Use consistent role prefix; never derive role from request input.

**Detection:** `rg -n "hasRole|hasAuthority|grantedAuthority" src/`

---

### 8. Open redirect in login/logout

**What:** `logoutSuccessUrl(request.getParameter("next"))` redirects to attacker site.

**Fix:** Allowlist redirect targets; reject absolute/external URLs.

**Detection:** `rg -n "logoutSuccessUrl|redirect:|sendRedirect\(.*request" src/`

---

### 9. Timing-safe comparison missing

**What:** Comparing tokens with `equals` leaks via timing.

**Fix:** Use `MessageDigest.isEqual` for token comparisons.

**Detection:** `rg -n "\.equals\(.*token|\.equals\(.*secret" src/`

---

### 10. Missing rate limiting / brute force on login

**What:** No lockout/throttle on auth endpoints.

**Fix:** Add rate limiting (bucket4j, filter) or integration with WAF/identity provider.

**Detection:** review auth controller for rate-limit filters.

---

### 11. Trusting `X-Forwarded-*` without proxy config

**What:** Using client IP from headers without trusted proxy config enables IP spoofing for allowlists.

**Fix:** Use `ForwardedHeaderFilter` only behind a trusted proxy; validate proxy chain.

**Detection:** `rg -n "X-Forwarded|ForwardedHeaderFilter|RemoteAddr" src/`

---

### 12. Overly broad CORS

**What:** `CorsConfiguration().allowedOrigins("*")` with `allowCredentials(true)`.

**Fix:** Allowlist origins; credentials only with explicit origins.

**Detection:** `rg -n "allowedOrigins|allowedOriginPatterns|allowCredentials" src/`

---

## Checklist

- [ ] Default-deny authz; explicit public paths
- [ ] CSRF enabled for session apps
- [ ] BCrypt/Argon2 password encoding
- [ ] JWT key from secret store; `none` alg rejected
- [ ] Session fixation protection; secure cookies
- [ ] Method-level authz where needed
- [ ] Consistent role prefix; no role from input
- [ ] Redirect targets allowlisted
- [ ] Constant-time token comparison
- [ ] Rate limiting on auth endpoints
- [ ] Trusted-proxy config for forwarded headers
- [ ] CORS allowlist explicit

## Quick detection bundle

```bash
rg -n "permitAll|anyRequest" src/
rg -n "csrf\(\)\.disable|csrf\.disable" src/
rg -n "NoOpPasswordEncoder|MD5|SHA1" src/
rg -n "Jwts|signWith|HS256" src/
rg -n "@PreAuthorize|@PostAuthorize|@EnableMethodSecurity" src/
rg -n "allowedOrigins|allowCredentials" src/
```
