# Vibe-Coded Apps — Secrets & Supply Chain

Defensive reference for the two most common high-impact failure modes in AI-generated code: hardcoded secrets and hallucinated/insecure dependencies.

---

## 1. Hardcoded secrets

### What it is
AI assistants frequently paste a real-looking API key, token, or connection string into source "to make the example work." These get committed and shared.

### Dangerous patterns
```js
const OPENAI_API_KEY = "sk-...";            // real key in source
const db = "postgres://user:pass@host/db";  // credentials in DSN
const stripeKey = process.env.STRIPE_KEY || "sk_test_..."; // fallback secret
```
```python
API_KEY = "AIza..."           # committed
SECRET_KEY = "dev"            # weak default
```
```go
const token = "ghp_..."       // committed PAT
```

### Why AI generates it
The assistant optimizes for a runnable example. It writes the key inline because that's what "works" in a single-file snippet, and it sometimes invents a plausible-looking key that happens to match the format of a real provider.

### What leaks
Cloud provider keys, DB credentials, payment provider keys, AI provider keys — each can be abused for fraud, data theft, or crypto-mining within minutes of being pushed to a public repo.

### Fix
- Load every secret from env / secret manager; never inline.
- Ship `.env.example` with empty placeholders only.
- No fallback secret values in code (`|| "sk_test_..."`).
- Pre-commit hook: `gitleaks` / `trufflehog` / `detect-secrets`.
- Rotate any key that was ever committed or pasted into a prompt.

### Detection
```bash
gitleaks detect --source . --no-banner
rg -n "sk-[a-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{34}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}" .
rg -n "(api|secret|token|password|key)\s*[:=]\s*['\"][A-Za-z0-9+/=._-]{12,}['\"]" app/
git ls-files | rg -i "creds|keys|secret|\.env$|adminsdk|firebase"
```

---

## 2. Hallucinated / typosquat packages

### What it is
AI sometimes invents package names that don't exist, or suggests names that are typosquats of popular packages. When a developer runs `npm install` / `pip install` to satisfy the import, an attacker-controlled package may be installed, or the build breaks on a name that resolves to malware.

### Dangerous patterns
```js
import { vaildate } from 'validatorjs';        // typo'd/imagined
import leftpad from 'left-pad-utils';          // typosquat of 'left-pad'
```
```python
import reqeusts                                  # typo
from python_cron_util import cron              # invented
```

### Why AI generates it
The assistant predicts the next likely token; package names are short and easy to mispredict. It also mixes up ecosystems (a JS helper name in Python, or a deprecated v3 API still cited as current).

### What leaks / impact
- Typosquat install → malware on the build host, supply-chain RCE, exfiltration of env/secrets during `postinstall`.
- Invented package that later gets registered by an attacker → future compromise.

### Fix
- Verify every import resolves to the official package (check the registry URL, download count, maintainer).
- Pin versions and ideally lockfile hashes (`package-lock.json` with `npm ci`, `pip-tools` pinned hashes, `go.sum`).
- Use `npm audit`/`pip-audit`/`osv-scanner`/`trivy` in CI.
- Prefer well-known packages; treat any unfamiliar import as a finding.

### Detection
```bash
npm ls --all | less                            # review unfamiliar names
pip freeze | xargs -I{} pip show {} | rg -i "Name:"
osv-scanner --lockfile=package-lock.json
osv-scanner --lockfile=requirements.txt
```
Cross-check each unfamiliar package name against the official registry and look for typosquat patterns (extra/missing letters, `-utils`, `-js`, `2`/`x` suffixes).

---

## 3. Outdated / vulnerable dependencies

### What it is
AI training data skews toward older, widely-copied snippets, so generated code often pins to versions with known CVEs (e.g., `axios@^0.19`, `lodash@^4.17.4`, `jsonwebtoken@^8`, `django@^2`, `express@^4.17.0` with unpatched middleware).

### Dangerous patterns
```json
{ "dependencies": { "axios": "^0.19.0", "lodash": "^4.17.4", "jsonwebtoken": "^8.5.1" } }
```
```txt
Django==2.2
Flask==1.0
PyYAML==5.1
```

### Why AI generates it
The assistant reproduces the most common version it saw in training, which is often years old and vulnerable.

### What leaks / impact
Known CVEs in those exact versions (prototype pollution, ReDoS, auth bypass, SSRF, RCE) — exploitable with public PoCs.

### Fix
- Update to current patched majors; test before bumping.
- Run `npm audit` / `pip-audit` / `snyk` / `trivy` in CI and fail on high/critical.
- Enable Dependabot/Renovate.
- Pin to a lockfile with hashes; use `npm ci` / `pip install --require-hashes`.

### Detection
```bash
npm audit --omit=dev
pip-audit -r requirements.txt
trivy fs .
snyk test
```

---

## 4. Secrets in client bundles

### What it is
Vibe-coded frontends often put a "backend" key into `NEXT_PUBLIC_*`, `REACT_APP_*`, `VITE_*`, or Angular `environment.ts`, assuming it's hidden. It isn't — it's inlined into the shipped JS.

### Dangerous patterns
```env
NEXT_PUBLIC_STRIPE_SECRET=sk_live_...
REACT_APP_OPENAI_KEY=sk-...
VITE_SUPABASE_SERVICE_ROLE=eyJ...
```

### Fix
- Only public-safe values (publishable keys, public maps key) go in `*_PUBLIC_*`.
- Server secrets stay server-side; the client calls your backend, which holds the secret.
- Audit the built bundle: `grep` the minified JS for key prefixes.

### Detection
```bash
rg -n "NEXT_PUBLIC_|REACT_APP_|VITE_" .env*
rg -n "sk_live_|sk-|service_role|admin|secret" dist/ build/ .next/static/
```

---

## 5. Committed config / IaC secrets

### What it is
AI-generated Terraform, Helm `values.yaml`, Docker Compose, or `.env` files often contain real credentials "to make the example complete."

### Dangerous patterns
```yaml
# values-prod.yaml
database:
  password: "SuperSecret123"      # committed
```
```hcl
provider "aws" {
  access_key = "AKIA..."          # committed
  secret_key = "wJalrX..."        # committed
}
```

### Fix
- Reference secrets from a secret manager / sealed-secrets / external-secrets / Vault.
- Use `sops` / `git-secrets` pre-commit.
- Rotate anything committed.

### Detection
```bash
git ls-files | xargs rg -n "AKIA[0-9A-Z]{16}|password\s*[:=]\s*['\"][^'\"]{6,}"
gitleaks detect --source .
```

---

## Checklist

- [ ] `gitleaks`/`trufflehog` pre-commit + CI
- [ ] No inline secrets; all from env/secret manager
- [ ] `.env.example` has empty placeholders only
- [ ] Every import verified against the official registry
- [ ] Lockfiles with hashes; `npm ci` / `pip install --require-hashes`
- [ ] `npm audit` / `pip-audit` / `osv-scanner` / `trivy` in CI
- [ ] Dependabot/Renovate enabled
- [ ] No server secrets in `*_PUBLIC_*` client env
- [ ] Built bundle audited for key prefixes
- [ ] IaC uses secret manager, not plaintext credentials
- [ ] Any committed secret rotated

## Quick detection bundle

```bash
gitleaks detect --source . --no-banner
rg -n "sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{34}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}" .
git ls-files | rg -i "creds|keys|secret|\.env$|adminsdk|firebase"
npm audit --omit=dev
pip-audit -r requirements.txt
osv-scanner --lockfile=package-lock.json
rg -n "NEXT_PUBLIC_|REACT_APP_|VITE_" .env*
rg -n "sk_live_|sk-|service_role|admin|secret" dist/ build/ .next/static/ 2>/dev/null
```
