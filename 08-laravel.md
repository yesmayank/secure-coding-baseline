# PHP + Laravel — Misconfigurations & Common Vulnerabilities

Defensive reference for Laravel applications.

---

## Misconfigurations

### 1. `APP_DEBUG=true` in production

**What:** Laravel's error page renders stack traces, env, and config — leaking `APP_KEY`, DB creds, and source paths.

**Fix:** `APP_DEBUG=false` in prod; `APP_KEY` from env, rotated if leaked.

**Detection:** `rg -n "APP_DEBUG|APP_KEY" .env config/*.php`

---

### 2. Weak/leaked `APP_KEY`

**What:** `APP_KEY` encrypts sessions, cookies, signed URLs. A leaked key lets attackers forge sessions and decrypt encrypted data.

**Fix:** `php artisan key:generate`; store in env; rotate if committed (re-encrypt affected data).

**Detection:** `rg -n "APP_KEY" .env`; `git ls-files | rg -i key`

---

### 3. APP_KEY used for passwords / weak hashing

**What:** Using `Crypt::encrypt` for passwords or `md5`/`sha1` for hashing.

**Fix:** Use `Hash::make` (bcrypt/argon2) for passwords; never encrypt-then-compare.

**Detection:** `rg -n "md5\(|sha1\(|Crypt::encrypt.*password" app/`

---

### 4. Storage/symlink exposure

**What:** `php artisan storage:link` makes `storage/app/public` web-accessible; private files placed there leak.

**Fix:** Keep private files outside `public/`; serve private files via a controller with auth.

**Detection:** `rg -n "storage:link|public_path|Storage::download" app/ routes/`

---

### 5. Verbose error display

**What:** `display_errors=On` or `debugbar` enabled in prod leaks stack traces and queries.

**Fix:** `display_errors=Off`; disable `barryvdh/laravel-debugbar` in prod.

**Detection:** `rg -n "debugbar|display_errors" config/ .env`

---

## Common Vulnerabilities

### 6. Mass assignment (fillable)

**What:** `Model::create($request->all())` without `$fillable` lets attackers set `is_admin`.

**Fix:** Define `$fillable` (allowlist); never `$guarded = []`.

**Detection:** `rg -n "request->all\(\)|::create\(|guarded\s*=" app/`

---

### 7. SQL injection via raw queries

**What:** `DB::raw("... WHERE id = ".$id)` or query builder with `whereRaw` interpolation.

**Fix:** Use bindings: `DB::raw("... WHERE id = ?", [$id])` or Eloquent.

**Detection:** `rg -n "DB::raw|whereRaw|selectRaw|havingRaw" app/`

---

### 8. BOLA / IDOR

**What:** `Model::find($id)` without ownership check.

**Fix:** `Model::where('user_id', Auth::id())->findOrFail($id)`.

**Detection:** `rg -n "::find\(|findOrFail\(" app/`

---

### 9. XSS via Blade `{!! !!}`

**What:** `{!! $user->bio !!}` outputs unescaped HTML.

**Fix:** Use `{{ }}` (auto-escaped); sanitize with a purifier before storing if HTML is required.

**Detection:** `rg -n "\{!!.*!!\}" resources/ app/`

---

### 10. CSRF disabled / excluded

**What:** `VerifyCsrfToken::$except` broad exclusions on state-changing routes.

**Fix:** Keep CSRF on; exclude only webhooks with signature verification.

**Detection:** `rg -n "except|VerifyCsrfToken|WithoutMiddleware" app/`

---

### 11. Insecure deserialization

**What:** `unserialize()` on untrusted data → RCE via gadget chains.

**Fix:** Use `json_encode`/`json_decode`; never `unserialize` untrusted input.

**Detection:** `rg -n "unserialize\(" app/`

---

### 12. Path traversal in file ops

**What:** `file_get_contents(storage_path($request->f))` with `..` escapes.

**Fix:** Validate filename; resolve and bounds-check against base dir.

**Detection:** `rg -n "file_get_contents\(.*request|storage_path\(.*request" app/`

---

### 13. Open redirect

**What:** `redirect($request->return_to)` to attacker site.

**Fix:** Allowlist redirect targets.

**Detection:** `rg -n "redirect\(.*request|return Redirect::to\(.*request" app/`

---

## Checklist

- [ ] `APP_DEBUG=false` in prod
- [ ] `APP_KEY` from env; rotated if leaked
- [ ] Bcrypt/argon2 for passwords
- [ ] Private files outside `public/`
- [ ] `display_errors=Off`; debugbar off in prod
- [ ] `$fillable` defined; no `$guarded=[]`
- [ ] Parameterized SQL
- [ ] Object lookups scoped by owner
- [ ] Blade `{{ }}` auto-escape; no `{!! !!}` on untrusted
- [ ] CSRF on; minimal exclusions
- [ ] No `unserialize` on untrusted data
- [ ] File paths bounds-checked
- [ ] Redirect targets allowlisted

## Quick detection bundle

```bash
rg -n "APP_DEBUG|APP_KEY" .env
rg -n "request->all\(\)|::create\(|guarded\s*=" app/
rg -n "DB::raw|whereRaw|selectRaw" app/
rg -n "::find\(|findOrFail\(" app/
rg -n "\{!!.*!!\}" resources/ app/
rg -n "unserialize\(" app/
```
