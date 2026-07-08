# ReconMind

> Intelligent Python-based Offensive Security Reconnaissance & Vulnerability Assessment Framework

ReconMind is a modular reconnaissance and vulnerability assessment framework built for authorized security testing and bug bounty research.

Unlike traditional diff-based scanners, ReconMind focuses on **context-aware analysis**, **response intelligence**, and **confidence-based validation** to reduce false positives while assisting security researchers in identifying real security issues.

---

## Features

### Intelligent Recon Engine

- Smart URL crawling
- Parameter discovery
- Reflection detection
- Response collection
- Automatic parameter mutation
- Passive reconnaissance
- Active reconnaissance

---

### Supported Modules

- Reflected XSS
- IDOR
- SQL Injection
- SSRF
- LFI
- Open Redirect
- Reflection Analysis

---

### Phase 5 XSS Intelligence

ReconMind includes an intelligent XSS validation pipeline featuring:

- Context Detection Engine
- Reflection Classification
- Encoding Detection
- Breakout Analysis
- Exploitability Scoring
- Confidence Engine
- Context-Aware Payload Selection
- Evidence-Based Reporting

Instead of reporting every reflection, ReconMind evaluates whether a reflection is actually exploitable.

---

## Scanner Architecture

```
ReconMind
│
├── Passive Recon
├── Active Recon
├── Smart Crawler
├── Parameter Extraction
├── Response Intelligence
│
├── Reflection Module
├── XSS Engine
├── SQLi Module
├── IDOR Module
├── SSRF Module
├── LFI Module
├── Redirect Module
│
├── Confidence Engine
├── Similarity Engine
├── Baseline Calibration
├── Response Normalization
│
├── Reporting
└── SQLite Database
```

---

## Current Development

Current Phase

**Phase 5 — Intelligent XSS Validation**

Completed:

- Smart Recon Engine
- Reflection Detection
- Response Intelligence
- Similarity Engine
- Confidence Scoring
- Context Detection
- Breakout Analyzer
- Encoding Detection
- Evidence Models
- Database Integration
- JSON Reporting
- Markdown Reporting

---

## Planned Roadmap

### Phase 6

- DOM XSS
- Blind XSS
- Better SQLi Validation
- Better SSRF Validation
- Improved IDOR Validation

### Phase 7

- GraphQL Security
- JWT Analysis
- API Security
- SSTI Detection
- XXE Detection

### Phase 8

- Plugin System
- Parallel Scanning
- Custom Detection Rules
- Machine Learning Assisted Prioritization
- Interactive Dashboard

---

## Installation

```bash
git clone https://github.com/wamiqhilal61-sudo/ReconMind.git

cd ReconMind

pip install -r requirements.txt
```

---

## Usage

Single URL

```bash
python main.py -u "https://example.com/search?q=test"
```

Debug Mode

```bash
python main.py -u "https://example.com/search?q=test" --debug
```

Proxy through Burp Suite

```bash
python main.py -u "https://example.com/search?q=test" --proxy http://127.0.0.1:8080
```

Save JSON Report

```bash
python main.py -f urls.txt --save-json
```

---

## Philosophy

ReconMind is designed around one principle:

> Detect evidence, not differences.

Instead of assuming that every response difference indicates a vulnerability, ReconMind evaluates multiple signals before assigning a confidence score.

This approach significantly reduces false positives and provides more actionable findings.

---

## Technologies

- Python
- Requests
- BeautifulSoup
- SQLite
- Git
- Burp Suite
- OWASP Methodologies

---

## Disclaimer

ReconMind is intended **only for authorized security testing, educational purposes, and bug bounty programs that explicitly permit automated testing.**

Do **not** use this tool against systems without permission.

---

## Author

**Wamiq Hilal**

- Offensive Security Enthusiast
- Web Application Security
- Bug Bounty Research
- B.Tech Computer Science

GitHub

https://github.com/wamiqhilal61-sudo
