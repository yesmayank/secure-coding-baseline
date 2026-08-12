# PHP (raw / PDO) — Misconfigurations & Common Vulnerabilities

Defensive reference for PHP applications without a framework.

---

## Misconfigurations

### 1. `display_errors=On` in production

**What:** PHP error output renders file paths, line numbers, and sometimes config/SQL in the HTTP response.

**Fix:** `display_errors=Off`, `log_errors=On` in prod.

**Detection:** `rg -n "display_errors|error_reporting" php.ini .htaccess`

---

### 2. `expose_php=On`

**What:** Adds `X-Powered-By: PHP/x.y` header — fingerprinting.

**Fix:** `expose_php=Off`.

**Detection:** `rg -n "expose_php" php.ini`

---

### 3. `allow_url_include=On`

**What:** Allows `include`/`require` of remote URLs → RFI → RCE.

**Fix:** `allow_url_include=Off` (default), `allow_url_fopen=Off` if possible.

**Detection:** `rg -n "allow_url_include|allow_url_fopen" php.ini`

---

### 4. Sensitive files in web root

**What:** `.sql` dumps, `config.php`, backups, `.git/` reachable under the docroot.

**Fix:** Keep config and data outside docroot; deny dotfiles in web server config.

**Detection:** `ls -la public/`; check web server config for dotfile rules.

---

### 5. Sessions with insecure cookie params

**What:** Default `session.cookie_httponly=0`, `cookie_secure=0`, `cookie_samesite=` enables theft/CSRF.

**Fix:** `session.cookie_httponly=1`, `cookie_secure=1`, `cookie_samesite=Strict`, `use_strict_mode=1`.

**Detection:** `rg -n "cookie_httponly|cookie_secure|cookie_samesite" php.ini`

---

## Common Vulnerabilities

### 6. SQL injection via string concatenation

**What:** `mysqli_query($c, "SELECT ... WHERE id = ".$_GET['id'])` is classic SQLi.

**Fix:** PDO prepared statements with bound params.
```php
$stmt = $pdo->prepare("SELECT ... WHERE id = ?");
$stmt->execute([$id]);
```

**Detection:** `rg -n "mysqli_query\(.*\.\$_|query\(.*\.\$_|->query\(.*\$_" *.php`

---

### 7. XSS via unescaped output

**What:** `echo $_GET['name']` outputs raw HTML.

**Fix:** `echo htmlspecialchars($val, ENT_QUOTES, 'UTF-8')` in the correct context; use a templating layer.

**Detection:** `rg -n "echo \$_|echo \$.*\$_" *.php`

---

### 8. Command injection

**What:** `system("convert ".$_FILES['f']['name'])` runs shell with user input.

**Fix:** Use `escapeshellarg()`; prefer `proc_open` with arg arrays; validate input.

**Detection:** `rg -n "system\(|exec\(|shell_exec\(|passthru\(|popen\(" *.php`

---

### 9. File upload abuse

**What:** Accepting any extension/MIME → upload of `.php` webshell.

**Fix:** Allowlist extensions; verify MIME via `finfo`; store outside docroot; randomize names; disable script execution in upload dir.

**Detection:** `rg -n "move_uploaded_file|\$_FILES" *.php`

---

### 10. Path traversal / LFI

**What:** `include($_GET['page'].".php")` enables LFI and traversal.

**Fix:** Allowlist pages; resolve and bounds-check; never `include` user input.

**Detection:** `rg -n "include\(.*\$_|require\(.*\$_|include_once\(.*\$_" *.php`

---

### 11. Insecure deserialization

**What:** `unserialize($_GET['x'])` → RCE via `__wakeup`/`__destruct` gadgets.

**Fix:** Use `json_encode`/`json_decode`.

**Detection:** `rg -n "unserialize\(" *.php`

---

### 12. `extract()` / `parse_str` superglobals pollution

**What:** `extract($_GET)` or `parse_str($_SERVER['QUERY_STRING'])` overwrites variables.

**Fix:** Avoid `extract` on superglobals; use `filter_input`.

**Detection:** `rg -n "extract\(|parse_str\(" *.php`

---

### 13. Weak crypto / `rand`

**What:** `md5` for hashing, `rand()` for tokens.

**Fix:** `password_hash`/`password_verify`; `random_bytes`/`random_int` for tokens.

**Detection:** `rg -n "md5\(|sha1\(|rand\(|mt_rand\(" *.php`

---

## Checklist

- [ ] `display_errors=Off`; `log_errors=On`
- [ ] `expose_php=Off`
- [ ] `allow_url_include=Off`
- [ ] Config/data outside docroot; dotfiles denied
- [ ] Secure session cookie params
- [ ] PDO prepared statements everywhere
- [ ] All output context-encoded
- [ ] No shell with user input; `escapeshellarg`
- [ ] File uploads allowlisted + validated + stored outside docroot
- [ ] No `include`/`require` of user input
- [ ] No `unserialize` of untrusted data
- [ ] No `extract`/`parse_str` on superglobals
- [ ] `password_hash` + `random_bytes`

## Quick detection bundle

```bash
rg -n "display_errors|expose_php|allow_url_include" php.ini
rg -n "mysqli_query\(.*\.\$_|query\(.*\.\$_|->query\(.*\$_" *.php
rg -n "system\(|exec\(|shell_exec\(|passthru\(" *.php
rg -n "include\(.*\$_|require\(.*\$_" *.php
rg -n "unserialize\(|extract\(|parse_str\(" *.php
rg -n "md5\(|sha1\(|rand\(|mt_rand\(" *.php
```
