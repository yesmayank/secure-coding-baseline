# Vibe-Coded Apps — Authentication & Authorization

Defensive reference for auth failures that recur in AI-generated code. The pattern: authentication ("can you log in?") is generated; authorization ("can you do *this*?") is not.

---

## 1. Weak or fake authentication

### What it is
AI often produces a login route that "looks right" but doesn't actually verify credentials, or compares passwords in plaintext.

### Dangerous patterns
```js
// Looks like login; doesn't actually check the password
app.post('/login', (req, res) => {
  const user = users.find(u => u.email === req.body.email);
  if (user) return res.json({ token: sign(user) });   // no password check
});
```
```python
if user and user.password == request.json['password']:   # plaintext compare
    ...
```
```js
if (password === 'admin123') { ... }                      # hardcoded
```

### Fix
- Always `bcrypt.compare`/`argon2.verify` the submitted password against the stored hash.
- Never store or compare plaintext passwords.
- Require both identifier and secret; reject on any mismatch with constant-time compare.

### Detection
```bash
rg -n "if \(.*\.password ==|\.password ===|password == ['\"]" app/
rg -n "bcrypt\.compare|argon2\.verify|password_verify" app/   # confirm present
```

---

## 2. Missing object-level authorization (BOLA / IDOR)

### What it is
The most common vibe-coded flaw. The generated CRUD handler fetches by `id` without checking that the caller owns the resource.

### Dangerous patterns
```js
app.get('/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);   // any user, any id
  res.json(order);
});
```
```python
def get_order(request, id):
    return Order.objects.get(pk=id)                    # no owner check
```

### Why AI generates it
The prompt was "make an orders API"; the assistant builds the happy path. Ownership checks require knowing the data model and the threat model, which weren't in the prompt.

### What leaks
Every other user's records — full horizontal privilege escalation. This is the single most reported bug class in AI-generated apps.

### Fix
- Scope every lookup by the authenticated user:
```js
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
if (!order) return res.status(404).send('Not found');
```
```python
Order.objects.get(pk=id, user=request.user)
```
- Prefer UUIDs over sequential IDs to reduce enumeration, but **do not** treat UUIDs as authorization.
- Add a test: "user A cannot read user B's resource."

### Detection
```bash
rg -n "findById|\.find\(.*id\)|\.get\(pk=|find_by\(id" app/
rg -n "@PathVariable.*id|@Param\('id'\)|req\.params\.id" app/
```
Review each hit for an ownership filter.

---

## 3. Mass assignment

### What it is
Binding the full request body to a model lets attackers set privileged fields (`role`, `isAdmin`, `price`, `ownerId`).

### Dangerous patterns
```js
const user = await User.create(req.body);                 // Node/Sequelize
```
```python
user = User(**request.json)                                # Flask
User.objects.create(**request.POST)                        # Django
```
```ruby
user.update(params[:user])                                 # Rails without strong params
```
```csharp
_context.Update(model);                                    # ASP.NET bound entity
```

### Why AI generates it
It's the shortest path from "I got JSON" to "I saved a row." The assistant rarely adds an allowlist unless asked.

### Fix
- Allowlist fields explicitly (DTO + mapper, `$fillable`, strong params, `[Bind]`, `excludeExtraValues`).
- Put privileged fields (`role`, `isAdmin`) in a separate admin-only code path.

### Detection
```bash
rg -n "create\(.*req\.|create\(.*request\.|create\(.*body|update\(.*req\.|update\(.*request\.|update\(.*body" app/
rg -n "\*\*request\.|\*\*req\.|\*\*body|\.update\(params\[" app/
rg -n "guarded\s*=\s*\[\]|fillable|permit\(" app/        # confirm allowlists exist
```

---

## 4. JWT misuse

### What it is
Vibe-coded auth frequently: stores JWTs in `localStorage` (XSS-exfiltratable), signs with a hardcoded/weak secret, accepts `alg: none`, or sets a year-long expiry.

### Dangerous patterns
```js
const token = jwt.sign({ id }, "secret");                 // hardcoded weak secret
localStorage.setItem('token', token);                     // XSS-exfil
// verifying without pinning the algorithm
jwt.verify(token, secret, { algorithms: [] });            // empty = some libs default to allow none
```

### Fix
- Short-lived access token (minutes) + httpOnly, Secure, SameSite=Strict cookie; refresh-token rotation.
- Strong secret from env (or asymmetric keys); explicitly pass `algorithms: ['HS256']` (or RS256) on verify.
- Reject `alg: none`; validate `iss`, `aud`, `exp`.

### Detection
```bash
rg -n "jwt\.sign\(.*['\"][^'\"]{1,32}['\"]" app/          # short/hardcoded secret
rg -n "localStorage\.setItem.*token|sessionStorage\.setItem.*token" app/
rg -n "algorithms:\s*\[\s*\]|verify\(.*\)" app/
```

---

## 5. Missing rate limiting / brute-force protection

### What it is
AI rarely adds rate limiting unless asked. Login, OTP, and password-reset endpoints become brute-forceable.

### Fix
- Rate-limit auth, OTP verify, and reset endpoints (per-IP and per-identifier).
- Add lockout / exponential backoff; cap OTP attempts.
- Use `express-rate-limit`, `slowapi`, `rack-attack`, `AspNetCoreRateLimit`, or a WAF.

### Detection
```bash
rg -n "rate.?limit|rateLimit|slowapi|Throttle|rack-attack" app/
```
Absence on login/OTP/reset routes is a finding.

---

## 6. Session fixation / weak session config

### What it is
Sessions not rotated on login; cookies without `HttpOnly`/`Secure`/`SameSite`.

### Fix
- Rotate session ID on privilege change (login, privilege escalation).
- `HttpOnly; Secure; SameSite=Strict`; `__Host-` prefix.

### Detection
```bash
rg -n "changeSessionId|regenerate|session_regenerate_id|SameSite|cookieHttpOnly|cookieSecure" app/
```

---

## 7. Insecure password reset / OTP

### What it is
Reset tokens that are predictable, never expire, or are sent in URL fragments; OTPs that are sequential or 4-digit without attempt limits.

### Fix
- Cryptographically random tokens (`secrets.token_urlsafe` / `crypto.randomBytes`); single-use; short TTL; invalidate on use; rate-limit verification.

### Detection
```bash
rg -n "Math\.random|rand\(\)|random_int|uuid1\(" app/
rg -n "reset.*token|otp|verify.*code" app/
```

---

## 8. Trusting client-supplied identity

### What it is
Using `req.body.userId` or a header like `X-User-Id` as the identity instead of the verified session/token.

### Dangerous patterns
```js
const userId = req.headers['x-user-id'];   // spoofable
app.delete('/account', (req, res) => {
  Account.deleteOne({ _id: req.body.accountId, userId: req.body.userId });
});
```

### Fix
- Identity comes only from the verified token/session (`req.user.id`), never from the request body or a client header.

### Detection
```bash
rg -n "req\.body\.(userId|user_id|ownerId)|req\.headers\['x-user-id'\]|x-user-id" app/
```

---

## 9. Role checks based on user-supplied data

### What it is
`if (req.body.role === 'admin')` or trusting a `role` field in the JWT that the client can tamper with (if the signature is weak/none).

### Fix
- Roles come from the server-side verified token or DB, never from the request body.
- Enforce server-side: `@PreAuthorize`, `requireRole`, guards.

### Detection
```bash
rg -n "req\.body\.role|request\.json\['role'\]|params\[:role\]" app/
```

---

## 10. Insecure OAuth / social login

### What it is
Missing state parameter, accepting `state` from the URL, not validating the CSRF token, or trusting the provider's email without verifying it.

### Fix
- Always send and verify `state`; use PKCE for all flows; verify email ownership before linking accounts; don't auto-link accounts by email.

### Detection
```bash
rg -n "state|pkce|oauth|passport" app/
```

---

## Checklist

- [ ] Passwords verified with bcrypt/argon2
- [ ] Every `:id` route scoped by authenticated owner
- [ ] No raw body bound to models (allowlists everywhere)
- [ ] JWT short-lived, httpOnly cookie, strong secret, pinned algorithm
- [ ] Rate limiting on login/OTP/reset
- [ ] Session ID rotated on login; secure cookie attrs
- [ ] Reset tokens/OTPs random, single-use, short TTL, rate-limited
- [ ] Identity from verified token only, never client body/header
- [ ] Roles from server, never request body
- [ ] OAuth uses state + PKCE; emails verified before linking

## Quick detection bundle

```bash
rg -n "if \(.*\.password ==|\.password ===|password == ['\"]" app/
rg -n "findById|\.find\(.*id\)|\.get\(pk=|find_by\(id" app/
rg -n "create\(.*req\.|create\(.*request\.|update\(.*req\.|\*\*request\.|\*\*req\." app/
rg -n "jwt\.sign\(.*['\"][^'\"]{1,32}['\"]" app/
rg -n "localStorage\.setItem.*token|sessionStorage\.setItem.*token" app/
rg -n "req\.body\.(userId|user_id|ownerId)|x-user-id|req\.body\.role" app/
rg -n "Math\.random|rand\(\)|uuid1\(" app/
```
