# Ruby on Rails — Misconfigurations & Common Vulnerabilities

Defensive reference for Rails applications.

---

## Misconfigurations

### 1. `config.consider_all_requests_local = true` in production

**What:** Renders full stack traces and route info on exceptions — source/config leak.

**Fix:** `false` in `config/environments/production.rb` (default); verify overrides.

**Detection:** `rg -n "consider_all_requests_local" config/`

---

### 2. `secret_key_base` committed

**What:** Signs/encrypts sessions and cookies. Leaked key → session forgery.

**Fix:** Load from env/credentials; rotate if committed.

**Detection:** `rg -n "secret_key_base" config/`; `git ls-files | rg -i secret`

---

### 3. `config.action_dispatch.show_exceptions` misconfigured

**What:** Showing full exceptions in prod leaks traces.

**Fix:** `config.action_dispatch.show_exceptions = :none` (or `:remote`) in prod; `public_file_server.enabled = false` when serving via nginx.

**Detection:** `rg -n "show_exceptions|public_file_server" config/`

---

### 4. `protect_from_forgery` disabled

**What:** Removing `protect_from_forgery` in `ApplicationController` disables CSRF.

**Fix:** Keep it; for APIs use token auth and disable CSRF only on JSON endpoints intentionally.

**Detection:** `rg -n "protect_from_forgery|skip_forgery_protection" app/`

---

### 5. Verbose asset/source exposure

**What:** Shipping `coverage/`, `tmp/`, `log/`, or `.git` under the docroot.

**Fix:** Keep these outside `public/`; nginx deny dotfiles.

**Detection:** `ls -la public/`

---

## Common Vulnerabilities

### 6. Mass assignment (strong params bypass)

**What:** `Model.new(params[:model])` without `require`/`permit`.

**Fix:** Always use strong params: `params.require(:user).permit(:name, :email)`.

**Detection:** `rg -n "params\[:|\.new\(params|\.update\(params" app/`

---

### 7. SQL injection via raw/order/where interpolation

**What:** `Model.where("name = '#{q}'")` or `order("#{params[:sort]}")`.

**Fix:** Use parameterized: `where(name: q)`; for order use allowlist of columns.

**Detection:** `rg -n "where\(\".*#\{|order\(.*#\{|find_by_sql" app/`

---

### 8. BOLA / IDOR

**What:** `Model.find(params[:id])` without ownership.

**Fix:** `current_user.items.find(params[:id])` (scoped query).

**Detection:** `rg -n "\.find\(params\[:id\]\)|find_by\(id:" app/`

---

### 9. XSS via `raw` / `html_safe`

**What:** `<%= raw user.bio %>` or `user.bio.html_safe` outputs unescaped HTML.

**Fix:** Use `<%= %>` (auto-escaped); sanitize with `sanitize` helper with an allowlist.

**Detection:** `rg -n "raw |html_safe|<%==" app/ app/views/`

---

### 10. Unsafe deserialization (Marshal/YAML)

**What:** `Marshal.load` / `YAML.load` (unsafe) on untrusted data → RCE.

**Fix:** Use `JSON`; `YAML.safe_load` with explicit permitted classes.

**Detection:** `rg -n "Marshal\.load|Marshal\.restore|YAML\.load\(" app/`

---

### 11. Command injection via backticks / `system`

**What:** `system("convert #{filename}")` interpolates user input.

**Fix:** Use `system("convert", filename)` (array form, no shell); `Shellwords.escape`.

**Detection:** `rg -n "system\(.*#\{|`.*#\{|exec\(.*#\{|IO\.popen" app/`

---

### 12. SSRF via `URI.parse` + HTTP

**What:** `Net::HTTP.get(URI(user_url))` hits internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "Net::HTTP|HTTParty|Faraday|open\(.*request" app/`

---

### 13. Path traversal in file send

**What:** `send_file(Rails.root.join("uploads", params[:f]))` with `..`.

**Fix:** Validate filename; `File.basename`; resolve and bounds-check.

**Detection:** `rg -n "send_file|File\.read\(.*params" app/`

---

## Checklist

- [ ] `consider_all_requests_local = false` in prod
- [ ] `secret_key_base` from env; rotated if leaked
- [ ] `show_exceptions` set to `:none`/`:remote`
- [ ] `protect_from_forgery` enabled
- [ ] No sensitive dirs under `public/`
- [ ] Strong params on every controller
- [ ] Parameterized SQL; allowlisted order columns
- [ ] Object lookups scoped by owner
- [ ] No `raw`/`html_safe` on untrusted
- [ ] No `Marshal`/unsafe `YAML.load`
- [ ] Shell commands use array form
- [ ] Outbound HTTP allowlisted
- [ ] File paths bounds-checked

## Quick detection bundle

```bash
rg -n "consider_all_requests_local|show_exceptions" config/
rg -n "secret_key_base" config/
rg -n "protect_from_forgery|skip_forgery_protection" app/
rg -n "where\(\".*#\{|order\(.*#\{|find_by_sql" app/
rg -n "\.find\(params\[:id\]\)" app/
rg -n "raw |html_safe|<%==" app/
rg -n "Marshal\.load|YAML\.load\(" app/
rg -n "system\(.*#\{|`.*#\{" app/
```
