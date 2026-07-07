# ReconMind

**Intelligent Bug Hunting & Reconnaissance Framework**

> For authorized security testing and educational use only.
> Never test targets without explicit written permission.

---

## Phase 1 — Parameter Extraction & Reflection Analysis

### What Phase 1 Does

```
User Input (URL or file)
        │
        ▼
┌─────────────────────┐
│   URL Handler       │  Normalize, validate, deduplicate
└────────┬────────────┘
         │  URLTarget objects
         ▼
┌─────────────────────┐
│  Param Extractor    │  GET / POST / Hidden / JSON params
└────────┬────────────┘
         │  URLTarget with .parameters
         ▼
┌─────────────────────┐
│ Reflection Engine   │  Inject XSS123TEST → check response
└────────┬────────────┘
         │  List[ReflectionResult]
         ▼
┌─────────────────────┐
│ Context Analyzer    │  JS? HTML attr? Comment? JSON?
└────────┬────────────┘
         │  List[ContextAnalysis]
         ▼
┌─────────────────────┐
│  Risk Scorer        │  Additive score → HIGH/MEDIUM/LOW
└────────┬────────────┘
         │  List[ScoredFinding]
         ▼
┌─────────────────────┐
│  CLI Reporter       │  Colored terminal output
└─────────────────────┘
```

---

## Installation

```bash
git clone <repo>
cd ReconMind
pip install -r requirements.txt
```

---

## Usage

```bash
# Single URL
python main.py -u "https://example.com/search?q=test"

# File of URLs (one per line)
python main.py -f targets.txt

# Route through Burp Suite proxy
python main.py -u "https://example.com/search?q=test" --proxy http://127.0.0.1:8080

# Debug logging
python main.py -u "https://example.com/search?q=test" --debug

# Disable color (pipe to file)
python main.py -f targets.txt --no-color > results.txt

# Custom timeout
python main.py -f targets.txt --timeout 30
```

---

## Folder Structure

```
ReconMind/
│
├── main.py                     ← Pipeline orchestrator & CLI entry point
│
├── config/
│   └── settings.py             ← All configuration (timeouts, weights, thresholds)
│
├── core/
│   ├── recon/
│   │   └── url_handler.py      ← URL normalization, validation, deduplication
│   ├── extractor/
│   │   └── param_extractor.py  ← GET/POST/Hidden/JSON parameter extraction
│   ├── analyzer/
│   │   └── context_analyzer.py ← Reflection context classification
│   ├── scoring/
│   │   └── risk_scorer.py      ← Additive risk scoring engine
│   ├── reporting/
│   │   └── cli_reporter.py     ← Colored CLI output
│   └── utils/
│       ├── logger.py           ← Centralized logging factory
│       └── http_client.py      ← Shared HTTP session
│
├── modules/
│   ├── reflection/
│   │   └── reflection_engine.py ← Marker injection & response analysis
│   ├── xss/                    ← Phase 2: XSS payload testing
│   ├── redirects/              ← Phase 2: Open redirect testing
│   ├── lfi/                    ← Phase 2: LFI testing
│   ├── ssrf/                   ← Phase 2: SSRF testing
│   └── idor/                   ← Phase 2: IDOR detection
│
├── database/                   ← Phase 2: SQLite finding storage
├── reports/                    ← Output directory for scan artifacts
└── requirements.txt
```

---

## Data Flow — How Modules Communicate

Every module in the pipeline exchanges **typed data objects** — not raw
strings or dictionaries. This is the key architectural decision.

| Object | Created by | Consumed by |
|--------|-----------|-------------|
| `URLTarget` | `url_handler.py` | `param_extractor`, `reflection_engine`, `reporter` |
| `Parameter` | `param_extractor.py` | `reflection_engine`, `scorer`, `reporter` |
| `ReflectionResult` | `reflection_engine.py` | `context_analyzer`, `scorer` |
| `ContextAnalysis` | `context_analyzer.py` | `risk_scorer`, `reporter` |
| `ScoredFinding` | `risk_scorer.py` | `cli_reporter` |

---

## Risk Scoring Weights (Phase 1)

| Signal | Points |
|--------|--------|
| Input reflected in response | +20 |
| Reflection not HTML-encoded | +30 |
| JavaScript execution context | +50 |
| Dangerous JS sink nearby (eval, innerHTML) | +40 |
| HTML attribute context | +25 |
| Event handler attribute | +20 (bonus) |
| JSON response context | +15 |
| HTML comment context | +10 |
| Multiple reflections | +5 per occurrence (max +20) |
| Header reflection | +15 |

**Severity thresholds:**
- `≥ 70` → **HIGH** — Likely exploitable, investigate immediately
- `≥ 40` → **MEDIUM** — Investigate this session
- `≥ 10` → **LOW** — Document and retest
- `< 10` → **INFO** — Not actionable alone

All weights are tunable in `config/settings.py`.

---

## Extending the Framework

### Adding a new vulnerability module (Phase 2+)

1. Create your module file: `modules/xss/xss_tester.py`
2. Import `ScoredFinding` from `core.scoring.risk_scorer`
3. Import `URLTarget` from `core.recon.url_handler`
4. Define a `run(target: URLTarget) -> List[ScoredFinding]` function
5. Import and call it from `main.py` after the reflection stage

The shared `SESSION` from `core.utils.http_client` handles all HTTP.
The `CONFIG` singleton from `config.settings` handles all configuration.
The `get_logger(__name__)` from `core.utils.logger` handles all logging.

---

## Legal Notice

ReconMind is designed for:
- Authorized penetration testing engagements
- Bug bounty programs with defined scope
- Security research in lab environments you own
- Educational study of web vulnerability classes

Using this tool against systems you do not have explicit permission to
test is illegal under the Computer Fraud and Abuse Act (US), the
Computer Misuse Act (UK), and equivalent laws worldwide.
