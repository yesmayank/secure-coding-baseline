# Vibe-Coded Apps — Injection & Input Validation

Defensive reference for injection-class bugs that recur in AI-generated code. These are the bugs most likely to ship because the assistant writes the "obvious" version, which is usually the insecure one.

---

## 1. SQL injection

### What it is
String-concatenated or f-string queries instead of parameterized ones.

### Dangerous patterns
```js
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
```
```python
cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")
User.objects.raw(f"... WHERE name = '{name}'")
```
```ruby
User.where("name = '#{q}'")
```
```go
db.Query(fmt.Sprintf("... WHERE id = %s", id))
```

### Why AI generates it
Interpolation is the shortest readable form, and the assistant reproduces the most common snippet it saw — which is often insecure.

### Fix
- Parameterized queries / prepared statements / ORM.
```js
db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
```
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
```
- For `ORDER BY`/column names (which can't be parameters), use an allowlist.

### Detection
```bash
rg -n "query\(f\"|query\(f'|query\(.*\+|execute\(f\"|execute\(f'|execute\(.*\+|raw\(f\"|raw\(.*\+" app/
rg -n "where\(\".*#\{|where\(\".*\+|FromSqlRaw|ExecuteSqlRaw" app/
```

---

## 2. NoSQL injection

### What it is
Spreading the request body into a Mongo/Query filter lets attackers inject operators (`$ne`, `$gt`, `$regex`) to bypass auth or dump data.

### Dangerous patterns
```js
User.findOne({ ...req.body });                 // { "password": { "$ne": null } } bypasses
User.find({ email: req.query.email, password: req.query.password });
db.col.find({ $where: "this.name == '" + name + "'" });
```

### Fix
- Validate and cast every field; never spread raw body into a query.
- Reject keys starting with `$`; allowlist operators explicitly.
- Never use `$where` with user input.

### Detection
```bash
rg -n "find\(.*\.\.\.req|find\(.*\.\.\.body|findOne\(.*\.\.\.req|find\(\{ ?\.\.\." app/
rg -n "\$where|\$func|new Function" app/
```

---

## 3. Command injection

### What it is
Shell commands built with user input.

### Dangerous patterns
```js
exec(`convert ${req.file.originalname} out.png`);
execSync(`git clone ${url}`);
```
```python
os.system(f"convert {filename} out.png")
subprocess.call("convert " + name, shell=True)
```
```ruby
system("convert #{filename}")
`curl #{url}`
```
```go
exec.Command("sh", "-c", "convert "+name)
```

### Fix
- Use arg-array forms (no shell): `execFile("convert", [name])`, `subprocess.run(["convert", name])`, `exec.Command("convert", name)`.
- Validate and sanitize input; use `Shellwords.escape`/`escapeshellarg`.

### Detection
```bash
rg -n "exec\(|execSync\(|shell_exec\(|system\(|os\.system\(|popen\(|IO\.popen|exec\.Command\(\"sh\"|exec\.Command\(\"/bin/sh\"" app/
rg -n "subprocess\..*shell=True" app/
rg -n "`[^`]*#\{" app/
```

---

## 4. XSS (cross-site scripting)

### What it is
Rendering untrusted data as HTML without escaping.

### Dangerous patterns
```jsx
<div dangerouslySetInnerHTML={{ __html: user.bio }} />
```
```html
<div v-html="user.bio"></div>
```
```blade
{!! $user->bio !!}
```
```razor
@Html.Raw(user.Bio)
```
```python
return render_template_string(f"Hello {name}")
```
```php
echo $_GET['name'];
```

### Fix
- Use auto-escaping (`{{ }}`, `<%= %>`, `@Model.Foo`, default Blade `{{ }}`).
- If HTML is required, sanitize with DOMPurify before storing/rendering.
- Validate `href`/`src` URLs to `http:`/`https:`; reject `javascript:`.

### Detection
```bash
rg -n "dangerouslySetInnerHTML|v-html|\{!!.*!!\}|Html\.Raw|render_template_string\(.*\{|echo \$_|echo \$.*\$_" app/
rg -n "href=\{.*\}|src=\{.*\}|style=\{.*\}" app/
```

---

## 5. SSTI (server-side template injection)

### What it is
Treating user input as a template body.

### Dangerous patterns
```python
render_template_string(f"Hello {name}")          # Flask/Jinja2 → RCE
render_template_string(request.args['t'])
```

### Fix
- Pass user data as a variable, never as the template source.
```python
render_template_string("Hello {{ name }}", name=name)
```

### Detection
```bash
rg -n "render_template_string\(.*\{|render_template_string\(.*request|render_template_string\(.*req" app/
rg -n "Template\(.*request|Template\(.*req|new Template\(.*req" app/
```

---

## 6. Path traversal / LFI

### What it is
File reads/includes with user-controlled paths.

### Dangerous patterns
```js
res.sendFile(path.join(__dirname, req.query.f));
fs.readFile(path.join(UPLOADS, req.params.name));
```
```python
open(os.path.join(BASE, request.args['f']))
```
```php
include($_GET['page'].".php");
file_get_contents(storage_path($request->f));
```

### Fix
- Allowlist filenames; resolve and bounds-check against a fixed base.
```js
const base = path.resolve(UPLOADS);
const target = path.resolve(base, req.params.name);
if (target !== base && !target.startsWith(base + path.sep)) return res.status(400).end();
```
- Never `include`/`require` user input.

### Detection
```bash
rg -n "sendFile\(.*req|readFile\(.*req|readFile\(.*params|os\.path\.join\(.*req|open\(.*request|include\(.*\$_|require\(.*\$_|file_get_contents\(.*request" app/
```

---

## 7. SSRF (server-side request forgery)

### What it is
Server-side fetches of user-supplied URLs, hitting internal services and cloud metadata.

### Dangerous patterns
```js
const r = await fetch(req.query.url);
axios.get(req.body.target);
```
```python
requests.get(request.args['url'])
urllib.request.urlopen(url)
```
```go
http.Get(r.URL.Query().Get("url"))
```

### Fix
- Allowlist hosts; block link-local (`169.254.0.0/16`) and RFC1918 ranges; validate scheme (`http`/`https`).
- Disable redirects or re-validate after redirect; pin DNS where possible.

### Detection
```bash
rg -n "fetch\(.*req\.|fetch\(.*params\.|fetch\(.*query\.|axios\.(get|post)\(.*req\.|requests\.get\(.*req|urlopen\(.*req|http\.Get\(.*req|reqwest::get\(" app/
```

---

## 8. Insecure deserialization

### What it is
Native object deserialization of untrusted data → RCE.

### Dangerous patterns
```python
pickle.loads(base64.b64decode(req.body))   # Python RCE
yaml.load(data)                              # unsafe loader
```
```php
unserialize($_GET['x']);                     # PHP gadget chains
```
```ruby
Marshal.load(data)
```
```java
ObjectInputStream.readObject(data);
```
```js
funcster / node-serialize.unserialize(data);  # Node RCE
```

### Fix
- Use `json`/`json_decode`; `yaml.safe_load`; for Java, avoid native serialization or use a hardened alternative; never `unserialize`/`Marshal.load`/`pickle.loads` untrusted input.

### Detection
```bash
rg -n "pickle\.loads|yaml\.load\(|unserialize\(|Marshal\.load|ObjectInputStream|node-serialize|\.unserialize\(" app/
```

---

## 9. Prototype pollution

### What it is
Merging untrusted objects into objects pollutes `Object.prototype`, altering behavior of unrelated code (and in some libs → RCE).

### Dangerous patterns
```js
Object.assign({}, req.body);
lodash.merge(target, req.body);
qs.parse(qs, { allowPrototypes: true });
```

### Fix
- Reject `__proto__`/`constructor`/`prototype` keys; use `Object.create(null)`.
- Keep `lodash`/`qs`/`axios` patched; avoid `bodyParser.urlencoded({ extended: true })` unless needed.

### Detection
```bash
rg -n "Object\.assign\(.*body|Object\.assign\(.*req|lodash\.merge|\.merge\(.*body|allowPrototypes" app/
```

---

## 10. XXE (XML external entity)

### What it is
XML parsers that resolve external entities → file read / SSRF / DoS.

### Dangerous patterns
```java
DocumentBuilderFactory.newInstance();   // default may resolve entities
```
```python
ET.fromstring(data)                      # vulnerable on old Python
```
```php
simplexml_load_string($xml)
```

### Fix
- Disable DTDs and external entities in every parser (`DocumentBuilderFactory` features, `defusedxml`, `libxml_disable_entity_loader`, `XMLReaderSettings` with `DtdProcessing.Prohibit`).

### Detection
```bash
rg -n "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|simplexml_load_string|ElementTree|xml\.etree|libxml" app/
```

---

## 11. ReDoS

### What it is
Catastrophic-backtracking regexes on user input.

### Fix
- Avoid nested quantifiers `(a+)+`; test with `safe-regex`/`re2`; set timeouts; prefer non-backtracking parsers for untrusted input.

### Detection
```bash
rg -n "new RegExp\(|re\.compile\(|Regexp\.new\(" app/
```

---

## 12. Missing input validation / type confusion

### What it is
AI-generated handlers often accept `any`/`dict`/untyped params, so the app trusts whatever the client sends.

### Fix
- Validate every input with a schema (zod, class-validator, pydantic, marshmallow, dry-validation, FluentValidation).
- Reject unknown fields (`whitelist`/`forbidNonWhitelisted`/`extra='forbid'`).

### Detection
```bash
rg -n ": any|: dict|: object\b|req\.body(?!\.)" app/
```
Confirm a validation layer is applied on each route.

---

## Checklist

- [ ] All SQL parameterized
- [ ] No raw body spread into NoSQL queries; `$`-keys rejected
- [ ] No shell with user input; arg-array forms only
- [ ] No unescaped HTML output; DOMPurify where HTML is needed
- [ ] No `render_template_string` with user input
- [ ] File paths bounds-checked; no `include` of user input
- [ ] Outbound HTTP allowlisted (SSRF)
- [ ] No native deserialization of untrusted data
- [ ] No unsafe merges of request body (prototype pollution)
- [ ] XML parsers hardened (XXE)
- [ ] Regexes safe (ReDoS)
- [ ] Every input validated with a schema; unknown fields rejected

## Quick detection bundle

```bash
rg -n "query\(f\"|query\(f'|query\(.*\+|execute\(f\"|execute\(.*\+|raw\(.*\+" app/
rg -n "find\(.*\.\.\.req|find\(.*\.\.\.body|\$where" app/
rg -n "exec\(|execSync\(|shell_exec\(|system\(|os\.system\(|subprocess\..*shell=True|exec\.Command\(\"sh\"" app/
rg -n "dangerouslySetInnerHTML|v-html|\{!!.*!!\}|Html\.Raw|render_template_string\(.*\{" app/
rg -n "sendFile\(.*req|os\.path\.join\(.*req|open\(.*request|include\(.*\$_" app/
rg -n "fetch\(.*req\.|axios\..*\(.*req\.|requests\.get\(.*req|http\.Get\(.*req" app/
rg -n "pickle\.loads|yaml\.load\(|unserialize\(|Marshal\.load|ObjectInputStream" app/
rg -n "Object\.assign\(.*body|lodash\.merge|allowPrototypes" app/
```
