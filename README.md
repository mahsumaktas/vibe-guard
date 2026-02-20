# vibe-guard 🛡️

[![CI](https://github.com/mahsumaktas/vibe-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mahsumaktas/vibe-guard/actions)
[![PyPI](https://img.shields.io/pypi/v/vibe-guard?color=blue)](https://pypi.org/project/vibe-guard/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Security scanner for AI-generated (vibe-coded) code. Detects vulnerabilities and gives your project a **Vibe Score**.

You vibe-coded it. But is it safe?

## Features

- 🔑 **Hardcoded credentials** — detects API keys, passwords, tokens via entropy + regex
- 💉 **SQL injection** — flags string concatenation in queries
- 🖥️ **RCE risk** — catches `eval()`, `exec()`, `os.system()`, `subprocess.shell=True`
- 📊 **Vibe Score 0-100** — weighted severity formula, shareable badge
- 📝 **Markdown reports** — paste-ready for PRs and issue comments
- 🔕 **Inline ignore** — `# vibe-ignore` to suppress false positives (supports specific rules: `# vibe-ignore: rce_risk`)
- 🤖 **GitHub Action** — auto-comment on PRs

## Install

```bash
pip install vibe-guard
```

## Usage

```bash
vibe-guard scan ./src
vibe-guard scan . --output report.md
vibe-guard score              # just the Vibe Score
vibe-guard init               # generates .cursorrules / .windsurfrules for AI agents
```

## Example Output

```
vibe-guard v0.0.1

Scanning: ./src (12 files)

🔴 CRITICAL (2)
  app.py:14   — Hardcoded API key: sk-***
  db.py:31    — SQL string concatenation (injection risk)

🟡 WARNING (1)
  utils.py:88 — eval() detected

Vibe Score: 42 / 100  ⚠️ Needs attention

Run `vibe-guard scan --output report.md` to generate a full report.
```

## GitHub Action

```yaml
- uses: mahsumaktas/vibe-guard@main
  with:
    path: ./src
    fail-on: critical
    comment-pr: 'true'
```

## Roadmap

- [x] v0.0.1 — Project skeleton
- [x] v0.0.2 — Hardcoded credentials scanner
- [x] v0.0.3 — RCE risk detection
- [x] v0.0.4 — SQL injection detection
- [x] v0.0.5 — Vibe Score algorithm
- [x] v0.0.6 — Inline ignore comments
- [x] v0.0.7 — Markdown report output
- [x] v0.0.8 — GitHub Action + PR comment integration
- [ ] v0.1.0 — PyPI stable release
- [x] v0.1.1 — Client-side secret leak detection (e.g., `NEXT_PUBLIC_`, `VITE_` prefixing sensitive keys)
- [x] v0.1.2 — Platform token detection (Vercel, Railway, Cloudflare API tokens)
- [x] v0.1.3 — Supabase security scanner (`service_role` leak, lack of RLS)
- [x] v0.1.4 — Insecure vibe-coding defaults (e.g., `Access-Control-Allow-Origin: *`, `console.log(process.env)`)

## Contributing

PRs welcome! See [open issues](https://github.com/mahsumaktas/vibe-guard/issues).

## License

MIT
