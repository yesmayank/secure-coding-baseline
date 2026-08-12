# C# / ASP.NET Core — Misconfigurations & Common Vulnerabilities

Defensive reference for ASP.NET Core services.

---

## Misconfigurations

### 1. `ASPNETCORE_ENVIRONMENT=Development` in production

**What:** Dev mode shows detailed exception pages (`UseDeveloperExceptionPage`) and may expose stack traces, env, and source paths.

**Fix:** Set `ASPNETCORE_ENVIRONMENT=Production`; use `UseExceptionHandler("/Error")`.

**Detection:** check env/Dockerfile for `ASPNETCORE_ENVIRONMENT`; `rg -n "UseDeveloperExceptionPage" Program.cs Startup.cs`

---

### 2. Detailed errors enabled

**What:** `UseDeveloperExceptionPage` or `app.UseDatabaseErrorPage()` in prod leaks traces and SQL.

**Fix:** Only in dev; prod uses `UseExceptionHandler` with a generic error path.

**Detection:** `rg -n "DeveloperExceptionPage|DatabaseErrorPage|DetailedErrors" Program.cs Startup.cs`

---

### 3. Swagger exposed in production

**What:** `/swagger` leaks route/schema inventory.

**Fix:** Gate by env: `if (env.IsDevelopment()) app.UseSwagger();`

**Detection:** `rg -n "UseSwagger|SwaggerUI" Program.cs Startup.cs`

---

### 4. CORS allow-all with credentials

**What:** `AllowAnyOrigin().AllowCredentials()` is invalid but `AllowAnyOrigin` + `AllowAnyMethod/Header` is overly permissive.

**Fix:** Allowlist origins; `AllowCredentials` only with explicit origins.

**Detection:** `rg -n "AllowAnyOrigin|AllowCredentials|WithOrigins" Program.cs Startup.cs`

---

### 5. Static files served from web root with secrets

**What:** Default `UseStaticFiles` serves `wwwroot`; placing config/secrets there leaks them.

**Fix:** Keep secrets out of `wwwroot`; serve only intended assets.

**Detection:** `rg -n "UseStaticFiles|UseFileServer|wwwroot" Program.cs Startup.cs`

---

## Common Vulnerabilities

### 6. SQL injection via string concatenation

**What:** `$"SELECT ... WHERE id = {id}"` with `SqlCommand` or interpolated EF `FromSqlRaw`.

**Fix:** Use parameterized queries: `FromSqlInterpolated($"... WHERE id = {id}")` (safe interpolation) or `@param` with `SqlParameter`; prefer LINQ.

**Detection:** `rg -n "FromSqlRaw|ExecuteSqlRaw|SqlCommand\(.*\+|CommandText.*\+" src/`

---

### 7. Mass assignment / `[Bind]` misuse

**What:** Action parameter bound to an entity type lets attackers set `IsAdmin`.

**Fix:** Use `[Bind]` allowlist or DTOs; `[JsonIgnore]`/`[NeverAutoUpdate]` privileged fields.

**Detection:** `rg -n "\[Bind\]|public.*Entity.*model|Update.*model" src/`

---

### 8. BOLA / IDOR

**What:** `_context.Items.Find(id)` without ownership.

**Fix:** Scope by user: `_context.Items.Where(i => i.OwnerId == userId).FirstOrDefault(i => i.Id == id)`.

**Detection:** `rg -n "\.Find\(|FirstOrDefault\(.*id" src/`

---

### 9. XSS via `@Html.Raw`

**What:** `@Html.Raw(userInput)` in Razor outputs unescaped HTML.

**Fix:** Use `@Model.Foo` (auto-encoded); sanitize before `Raw`.

**Detection:** `rg -n "Html\.Raw" src/ Views/`

---

### 10. Deserialization RCE (BinaryFormatter, Newtonsoft polymorphic)

**What:** `BinaryFormatter.Deserialize` or `JsonConvert.DeserializeObject<object>` with `TypeNameHandling.All` on untrusted data → RCE.

**Fix:** Avoid `BinaryFormatter` (deprecated/unsafe); set `TypeNameHandling = None` for untrusted input.

**Detection:** `rg -n "BinaryFormatter|TypeNameHandling|JsonConvert\.DeserializeObject<object>" src/`

---

### 11. Open redirect

**What:** `Redirect(returnUrl)` with user-supplied `returnUrl`.

**Fix:** Allowlist local URLs; reject absolute/external.

**Detection:** `rg -n "Redirect\(.*returnUrl|Redirect\(.*request|LocalRedirect" src/`

---

### 12. SSRF via `HttpClient`

**What:** `HttpClient.GetAsync(userUrl)` hits internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "HttpClient|GetAsync\(.*url|PostAsync\(.*url" src/`

---

### 13. XXE via `XmlSerializer` / `XmlDocument`

**What:** Default `XmlDocument` may resolve external entities.

**Fix:** `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }`; use `XmlReader.Create` with safe settings.

**Detection:** `rg -n "XmlDocument|XmlSerializer|XmlReader" src/`

---

## Checklist

- [ ] `ASPNETCORE_ENVIRONMENT=Production`
- [ ] No developer exception page in prod
- [ ] Swagger gated by env
- [ ] CORS allowlist explicit
- [ ] Secrets out of `wwwroot`
- [ ] Parameterized SQL / LINQ
- [ ] DTOs or `[Bind]` allowlist
- [ ] Object lookups scoped by owner
- [ ] No `@Html.Raw` on untrusted
- [ ] No `BinaryFormatter`/`TypeNameHandling.All` on untrusted
- [ ] Redirect targets allowlisted
- [ ] Outbound HTTP allowlisted
- [ ] XML readers hardened

## Quick detection bundle

```bash
rg -n "UseDeveloperExceptionPage|UseSwagger" Program.cs Startup.cs
rg -n "AllowAnyOrigin|AllowCredentials" Program.cs Startup.cs
rg -n "FromSqlRaw|ExecuteSqlRaw|SqlCommand\(.*\+" src/
rg -n "Html\.Raw" src/ Views/
rg -n "BinaryFormatter|TypeNameHandling" src/
rg -n "Redirect\(.*returnUrl|Redirect\(.*request" src/
rg -n "HttpClient" src/
```
