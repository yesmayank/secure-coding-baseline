# Nginx — Misconfigurations & Common Vulnerabilities

Defensive reference for Nginx as a reverse proxy / static server.

---

## Misconfigurations

### 1. `autoindex on` on a served directory

**What:** Enables directory listing — exposes file inventory to anyone.

**Fix:** `autoindex off;` (default) for all locations; only enable on intentionally public listings.

**Detection:** `rg -n "autoindex on" *.conf`

---

### 2. Serving the project root / `root .`

**What:** `root /var/www/app;` pointing at a dir containing source/config leaks them if no `location` blocks restrict.

**Fix:** Serve only `public/` or `static/`; deny dotfiles and config files.

**Detection:** `rg -n "root |alias " *.conf`

---

### 3. Missing dotfile / hidden file protection

**What:** `.git/`, `.env`, `.htaccess` reachable leak source and secrets.

**Fix:**
```nginx
location ~ /\. { deny all; return 404; }
location ~ (\.env|\.git|\.htaccess|config\.php)$ { deny all; return 404; }
```

**Detection:** `rg -n "\\.|/\\." *.conf`

---

### 4. `proxy_pass` with user-influenced path / SSRF

**What:** `proxy_pass $http_x_target;` or regex captures proxying to user-controlled hosts → SSRF.

**Fix:** Proxy only to fixed upstreams; validate any variable-derived host against an allowlist.

**Detection:** `rg -n "proxy_pass \$|proxy_pass .*\$\{" *.conf`

---

### 5. Missing / weak TLS

**What:** Old protocols (`ssl_protocols SSLv3 TLSv1 TLSv1.1`), weak ciphers, no HSTS.

**Fix:** `ssl_protocols TLSv1.2 TLSv1.3;` modern ciphers; `add_header Strict-Transport-Security "max-age=31536000" always;`.

**Detection:** `rg -n "ssl_protocols|ssl_ciphers|Strict-Transport-Security" *.conf`

---

### 6. No rate limiting / no body size limit

**What:** Missing `limit_req` and `client_max_body_size` enables DoS and large uploads.

**Fix:** `limit_req_zone` + `limit_req`; `client_max_body_size 1m;`.

**Detection:** `rg -n "limit_req|client_max_body_size" *.conf`

---

## Common Vulnerabilities

### 7. Host header injection / open redirect

**What:** `return 301 https://$host$request_uri;` uses unvalidated `$host` → header injection / redirect abuse.

**Fix:** Use `$server_name` or a validated host; reject unknown hosts at the server level.

**Detection:** `rg -n "\$host" *.conf`

---

### 8. Path traversal via alias

**What:** `location /files { alias /data/files/; }` without trailing slash normalization can allow traversal; misconfigured `alias` + regex can escape.

**Fix:** Prefer `root` where possible; ensure trailing slashes; validate path. Use `internal` for protected locations.

**Detection:** `rg -n "alias |root " *.conf`

---

### 9. Missing security headers

**What:** No `X-Content-Type-Options`, `X-Frame-Options`, CSP, Referrer-Policy.

**Fix:** Add headers globally; tune CSP per app.

**Detection:** `rg -n "add_header" *.conf`

---

### 10. Proxying internal headers to upstream

**What:** Forwarding client `X-Forwarded-For`/`X-Real-IP` without sanitizing lets upstream trust spoofed IPs.

**Fix:** `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` and have upstream trust only nginx; set `proxy_set_header Host $host;`.

**Detection:** `rg -n "proxy_set_header" *.conf`

---

### 11. Exposed admin / status / metrics

**What:** `/status`, `/stub_status`, `/metrics`, admin locations reachable publicly.

**Fix:** `allow 10.0.0.0/8; deny all;` or bind to internal listener.

**Detection:** `rg -n "stub_status|/status|/metrics|/admin" *.conf`

---

### 12. Insecure `merge_slashes` / path normalization gaps

**What:** Default `merge_slashes on` can sometimes bypass upstream path-based ACLs by sending `//` or `../`.

**Fix:** Normalize upstream; be aware of upstream path interpretation; test with malformed paths.

**Detection:** `rg -n "merge_slashes" *.conf`

---

## Checklist

- [ ] `autoindex off`
- [ ] Serve only intended dirs
- [ ] Deny dotfiles and config files
- [ ] `proxy_pass` to fixed upstreams only
- [ ] TLS 1.2/1.3 + HSTS
- [ ] Rate limiting + body size limit
- [ ] Validate `$host` in redirects
- [ ] `alias`/`root` carefully configured
- [ ] Security headers added
- [ ] Forwarded headers sanitized
- [ ] Admin/status/metrics restricted
- [ ] Upstream path normalization tested

## Quick detection bundle

```bash
rg -n "autoindex on" *.conf
rg -n "root |alias " *.conf
rg -n "proxy_pass \$|proxy_pass .*\$\{" *.conf
rg -n "ssl_protocols|ssl_ciphers|Strict-Transport-Security" *.conf
rg -n "limit_req|client_max_body_size" *.conf
rg -n "\$host" *.conf
rg -n "stub_status|/status|/metrics|/admin" *.conf
```
