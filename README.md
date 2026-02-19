# vibe-guard 🛡️

> Security scanner for AI-generated (vibe-coded) code. Detects vulnerabilities and gives your project a **Vibe Score**.

You vibe-coded it. But is it safe?

## Install

```bash
pip install vibe-guard
```

## Usage

```bash
vibe-guard scan ./src
vibe-guard scan --file app.py
vibe-guard scan . --output report.md
```

## Example Output

```
vibe-guard v0.0.1

Scanning: ./src (12 files)

🔴 CRITICAL (2)
  app.py:14 — Hardcoded API key detected: sk-***
  db.py:31  — SQL string concatenation (injection risk)

🟠 HIGH (3)
  utils.py:8  — eval() with user input
  auth.py:22  — os.system() with unvalidated argument
  api.py:55   — Path traversal risk: open(user_input)

🟡 MEDIUM (5)
  handler.py:12 — Silent exception: except: pass
  ...

Vibe Score: 42 / 100
→ Caution: Several security issues found. Review before deploying.
```

## What It Detects

| Rule | Severity |
|------|----------|
| Hardcoded credentials / API keys | 🔴 Critical |
| `eval()` with user input | 🟠 High |
| SQL string concatenation | 🟠 High |
| `os.system()` with args | 🟠 High |
| `except: pass` (silent failures) | 🟡 Medium |
| Path traversal risks | 🟠 High |
| Debug code left in | 🟡 Medium |
| High TODO/FIXME ratio | 🟡 Medium |

## Status

🚧 v0.0.1 — Under active development

## License

MIT
