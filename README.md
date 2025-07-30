# 🔍 JSFlow AI - JavaScript Security Analysis Tool

**JSFlow AI** is an AI-powered command-line tool for performing security analysis on JavaScript code. It combines static regex-based pattern matching with OpenAI's GPT-4o for intelligent vulnerability detection, endpoint discovery, secret identification, and risk assessment.

---

## ⚙️ Key Features

- ✅ Recursive analysis for entire projects and multiple JS-based file types (`.js`, `.ts`, `.vue`, `.jsx`, etc.)
- 🔑 Advanced secret detection for cloud providers (AWS, Stripe, GitHub, Google, etc.)
- 🧠 AI-enhanced vulnerability analysis with GPT-4o
- 📚 OWASP Top 10 classification with exploit difficulty scoring
- 🧬 Data flow analysis: tracks input sources to dangerous sinks
- 📊 Interactive HTML and JSON reports with severity classification
- 🛠️ Professional-grade CLI with advanced filtering and customization

---

## 📦 Installation

```bash
git clone https://github.com/adce626/JsFlowAI.git
cd JsFlowAI
pip install -r requirements.txt
