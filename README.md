# 🛡️ ASTraGuard — BYOK Code Review Assistant

> Multi-LLM Bring-Your-Own-Key (BYOK) SAST & Generative AI Code Review Auditor for Java and Python (Problem Code: **JP-003**).

---

## 📌 Features & Architecture
- **Bring Your Own Key (BYOK) Multi-LLM**: Zero pre-baked keys. Connect using your own API key for **Google Gemini**, **OpenAI**, **Anthropic Claude**, **Groq Cloud**, **OpenRouter**, or custom OpenAI-compatible endpoints.
- **2-Step Audit Onboarding**:
  1. **Connect GitHub Repo**: Ingest public or private GitHub repositories (or use the built-in instant demo suite).
  2. **Provide BYOK Key**: Select your preferred AI model and enter your personal API key.
- **Verbal Code Health Rating**: Translates numeric scores (0–100) into intuitive executive verbal ratings (e.g. *💎 Pristine & Production-Ready*, *🟢 Solid & Stable*, *🟡 Fair — Moderate Risk*, *🟠 Degraded — High Vulnerability*, *🔴 Critical Failure — Unsafe*).
- **Exact File & Line Pinpointing**: Pinpoints the exact file and line number where each vulnerability or smell resides.
- **~60-Word AI Explainers**: Generates a concise, high-impact 60-word paragraph detailing the root cause, exploit risk, and score penalty.
- **Interactive Patch Diffing**: Side-by-side Before/After code patches with one-click Markdown audit report export.

---

## 🚀 Quickstart Guide

### 1. Run the Dashboard
```bash
streamlit run app.py
```

### 2. Perform an Audit in 2 Steps:
1. **Step 1**: Enter your target GitHub repo URL (e.g., `https://github.com/pallets/flask`) or select the pre-loaded sample.
2. **Step 2**: Choose your LLM provider (Gemini, OpenAI, Claude, Groq, OpenRouter) and enter your API Key.
3. Click **"🚀 Run Codebase Analysis"** to inspect health scores, verbal ratings, pinpointed lines, and ~60-word explainers!

---

## 📁 Project Directory Structure
```
code-sentinel-ai/
├── app.py                      # Streamlit 2-step BYOK UI & audit dashboard
├── core/
│   ├── repo_cloner.py          # GitHub cloning (with private PAT support) & file crawler
│   ├── static_scanner.py       # Bandit, Radon, AST analyzer & verbal rating engine
│   └── ai_patcher.py           # Multi-provider BYOK LLM router & 60-word explainer engine
├── demo_repos/
│   └── vulnerable_sample/      # Pre-packaged test suite for instant demos
│       ├── auth_service.py     # SQLi, secrets, MD5
│       └── report_engine.py    # Cyclomatic complexity, unclosed file handles
├── requirements.txt            # Project dependencies
└── README.md                   # Documentation
```

