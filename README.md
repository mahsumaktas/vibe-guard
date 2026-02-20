<div align="center">

# 🛡️ Vibe-Guard

**The security scanner built for the AI-generated code era ("Vibe Coding").**

[![CI](https://github.com/mahsumaktas/vibe-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mahsumaktas/vibe-guard/actions)
[![PyPI](https://img.shields.io/pypi/v/vibe-guard?color=blue)](https://pypi.org/project/vibe-guard/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*You vibe-coded it. But is it safe?*

</div>

---

## 💡 The Problem

Rapid AI-assisted development ("vibe coding") is incredibly fast but often prioritizes making things "just work" over strict security. AI agents frequently:
- "Fix" frontend errors by exposing backend secrets (`NEXT_PUBLIC_DATABASE_URL`).
- Expose "god-mode" keys like Supabase's `service_role` to the client.
- Commit cloud provider tokens (Vercel, Railway, GCP, Stripe) directly into code.
- Apply insecure shortcuts like `Access-Control-Allow-Origin: *` or `verify=False` to bypass frustrating errors.

**Vibe-Guard** is designed to catch these specific AI-generation anti-patterns before they reach your production environment.

---

## ✨ Key Features

- 🕵️‍♂️ **Modern Stack Secrets:** Detects exposed Vercel, Railway, Cloudflare, Supabase, Stripe, GCP, SendGrid, Twilio, and Discord tokens.
- 🚨 **Frontend Leak Detection:** Catches backend secrets disguised with `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_` prefixes.
- ☁️ **Supabase Security:** Flags exposed `service_role` keys and overly permissive RLS policies (`USING (true)`).
- 🔓 **Insecure Defaults:** Identifies dangerous AI shortcuts like `verify=False` and permissive CORS.
- 💉 **Classic Vulnerabilities:** Detects SQL injection risks and RCE vectors (`eval`, `os.system`, `subprocess(shell=True)`).
- 🤖 **AI Agent Integration:** Run `vibe-guard init` to create `.cursorrules` / `.windsurfrules` so your AI assistant self-audits its code in the background.
- 📊 **Beautiful Reports:** Generates rich Markdown reports with Vibe Scores, visual health bars (🟩🟩⬜⬜⬜), and inline code snippets.
- 🔕 **Granular Ignores:** Use `# vibe-ignore` or `# vibe-ignore: rule_id` to suppress false positives.

---

## 🚀 Installation

```bash
pip install vibe-guard
```

---

## 💻 Usage

Run Vibe-Guard locally to scan your workspace:

```bash
# Scan a specific directory
vibe-guard scan ./src

# Scan and generate a rich Markdown report
vibe-guard scan . --output report.md

# Just get the Vibe Score (0-100)
vibe-guard score
```

### 🤖 AI Assistant Integration (Cursor, Windsurf)

Make your AI assistant self-aware of its security mistakes! Run this once in your project root:

```bash
vibe-guard init
```
This generates configuration files (`.cursorrules`, `.windsurfrules`) instructing your AI agent to run `vibe-guard scan .` in the background and fix critical vulnerabilities *before* showing you the code.

---

## 📄 Example Markdown Report

Vibe-Guard generates highly readable reports perfect for Pull Requests:

> # 🛡️ Vibe-Guard Security Report
> 
> **Scan path:** `.`  
> **Vibe Score:** 🔴 **15/100** — Unsafe
> **Health:** 🟥🟥⬜⬜⬜⬜⬜⬜⬜⬜
> 
> ### 📊 Summary
> | Severity | Count |
> |----------|-------|
> | 🔴 Critical | 2 |
> | **Total** | **2** |
> 
> ## 🔍 Detailed Findings
> 
> ### 📄 `app/db.ts`
> 
> #### 🔴 Line 12: Client-side secret leak: Sensitive variable exposed to frontend bundle
> ```python
> const url = process.env.NEXT_PUBLIC_DATABASE_URL;
> ```
> > 💡 **Fix:** Remove the public prefix (e.g. NEXT_PUBLIC_) so it's not bundled in the client code
> 
> ---

---

## ⚙️ GitHub Action (CI/CD)

Prevent insecure vibe-coded PRs from being merged. Add this to your `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [pull_request]

jobs:
  vibe-guard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Vibe-Guard
        uses: mahsumaktas/vibe-guard@main
        with:
          path: .
          fail-on: 'critical'  # Fails the pipeline if critical issues are found
          comment-pr: 'true'   # Automatically posts the markdown report as a PR comment
```

---

## 🗺️ Roadmap

- [x] Hardcoded credentials & RCE risk detection
- [x] SQL injection detection
- [x] Advanced inline ignore comments
- [x] **v0.1.1** — Client-side secret leak detection (`NEXT_PUBLIC_` etc.)
- [x] **v0.1.2** — Modern platform token detection (Vercel, Cloudflare, Stripe, GCP, etc.)
- [x] **v0.1.3** — Supabase security scanner (`service_role` leaks, RLS checks)
- [x] **v0.1.4** — Insecure vibe-coding defaults (CORS, `verify=False`)
- [x] **v0.1.5** — `vibe-guard init` for AI agent `.cursorrules` self-auditing
- [x] GitHub Action + PR comment integration
- [ ] PyPI stable release (v1.0.0)

---

## 🤝 Contributing

Contributions are welcome! Whether it's adding new token regexes, improving the Vibe Score algorithm, or adding support for new frameworks, feel free to open a Pull Request.

See [open issues](https://github.com/mahsumaktas/vibe-guard/issues).

## 📜 License

[MIT](LICENSE)
