# AIComply

**Deterministic EU AI Act & GDPR Compliance Scanner — Ship regulated AI with auditable, cryptographically-signed evidence.**

[![PyPI version](https://img.shields.io/pypi/v/aicomply-cli.svg?color=blue)](https://pypi.org/project/aicomply-cli/)
[![CI Status](https://github.com/aiambo08/AIComply/actions/workflows/compliance.yml/badge.svg)](https://github.com/aiambo08/AIComply/actions/workflows/compliance.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-informational)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)

---

## 1. The Problem: Compliance as an Afterthought Is a Budget Crisis

### The Status Quo

Engineering teams building AI-powered products under the **EU AI Act (Regulation 2024/1689)** and **GDPR** face a structurally broken compliance process:

- **Manual legal reviews** performed *post-development* by external consultancies cost **€15,000–€80,000 per audit cycle** and take 4–12 weeks.
- **No automated tooling** exists to catch prohibited patterns (`import fer`, hardcoded API keys, missing logging, disabled TLS) at the time they are written—in the IDE or during CI/CD.
- Compliance obligations are buried in 144 pages of statutory text across two regulatory frameworks, requiring specialized legal-technical expertise to map to engineering artifacts.
- **Non-compliance penalties** are severe: up to **€35M or 7% of global annual turnover** for prohibited AI practices (Art. 5), and **€20M or 4%** for GDPR violations.

### The Operational & Financial Drain

| Pain Point | Current Cost |
|---|---|
| Post-development audit cycles | €15,000–€80,000 / audit |
| Senior engineering hours on manual compliance reviews | 20–80 hours per release |
| Rework cost after a legal finding forces architectural changes | Often >50% of original sprint |
| Non-compliance fine exposure (EU AI Act Art. 5) | Up to €35M or 7% global turnover |
| GDPR Art. 32 violation (hardcoded secrets, disabled TLS) | Up to €20M or 4% global turnover |

### The Risk of Inaction

AI Act enforcement began in **February 2025** (prohibited practices). High-risk system obligations for sectors including recruitment, credit scoring, biometric identification, and public services take effect from **December 2027**. Organizations shipping AI code without a systematic compliance gate are accumulating unpriced regulatory liability in every sprint.

---

## 2. The Solution: Compliance-by-Design, Not Compliance-by-Audit

**AIComply** is a deterministic static analysis engine that enforces EU AI Act and GDPR compliance *directly in the development workflow*—before code reaches production. It operates as:

1. A **CLI scanner** (`aicomply scan`) that runs in milliseconds on any repository.
2. A **GitHub Actions CI gate** that uploads findings to GitHub Advanced Security as SARIF, blocking non-compliant PRs automatically.
3. A **regulatory dossier generator** (`aicomply docgen`) that drafts the **Annex IV Technical Documentation** mandated by EU AI Act Art. 11—cutting weeks of manual work.

### Business Impact

- **Cost Efficiency:** Replaces periodic €15,000–€80,000 audit cycles with a zero-marginal-cost automated gate on every commit.
- **Risk Mitigation:** Cryptographically-signed SHA-256 findings provide court-admissible evidence of due diligence, critical for regulatory defense.
- **Time-to-Value:** From `pip install` to first compliant CI pipeline in under 10 minutes. Annex IV dossier generated in seconds rather than weeks.
- **Shift-Left Enforcement:** Violations are caught at the line they are introduced, not after months of downstream rework.

---

## 3. Key Architectural Features

- **Dual-engine static analysis:** Python AST visitor (`ast.NodeVisitor`) resolves multi-level import aliases (`from openai import AsyncOpenAI as AI`), chained attribute calls (`client.chat.completions.create`), class-level instantiation (`self.client = OpenAI()`), and absence patterns (LLM calls without a logging import in scope).
- **Secondary Regex scanner** for non-Python artifacts (`.env`, `.yaml`, `.json`, `.js`, `.ts`) with pre-compiled patterns for O(1) per-line evaluation.
- **Cross-engine deduplication:** A composite key `(rule_id, file_path, start_line)` prevents the same violation from being reported twice when both engines fire on the same line.
- **Deterministic SHA-256 evidence:** Each finding carries a cryptographic identifier derived from `rule_id`, `file_path`, `start_line`, `end_line`, `pattern_target`, and a CRLF/LF-normalized code snippet—producing identical hashes across Linux, macOS, and Windows.
- **20 production-grade YAML rules** mapped to EU AI Act Arts. 5, 9, 10, 11, 12, 13, 14, 15, 50 and GDPR Arts. 5, 9, 22, 32, with accurate penalty schedules.
- **SARIF v2.1.0 output** with `ruleIndex`, `partialFingerprints`, 1-indexed regions, and `helpUri` to EUR-Lex—fully compatible with GitHub Advanced Security and GitLab SAST.
- **Inline suppression** via `# aicomply:ignore RULE-ID` comments, with `ALL` wildcard support.
- **Per-repository configuration** via `.aicomply.yaml`: glob-based path exclusions, rule ignoring, and risk-tier enforcement thresholds.
- **Interactive risk classifier** (`aicomply assess`): a structured decision tree that determines EU AI Act risk tier (Prohibited → High Risk → Limited Risk → Minimal Risk) for any use case.

---

## 4. System Topology

```
 Source Repository
         │
         ▼
 ┌───────────────────────┐
 │   ScanEngine (engine) │  ← .aicomply.yaml config loaded & applied
 │   Path traversal &    │
 │   exclusion filtering │
 └──────┬──────────┬─────┘
        │          │
        ▼          ▼
 ┌──────────┐ ┌────────────┐
 │  Python  │ │ Non-Python │
 │  AST     │ │ Text/Regex │
 │  Scanner │ │ Scanner    │
 └──────┬───┘ └────┬───────┘
        └────┬─────┘
             │  Cross-engine deduplication (rule_id, file, line)
             ▼
 ┌───────────────────────┐
 │  SHA-256 Hasher       │  ← Per-finding + consolidated scan hash
 │  (evidence/hasher.py) │
 └───────────┬───────────┘
             │
             ▼
 ┌───────────────────────────────────────────────┐
 │  Reporter Layer                               │
 │  terminal · json · markdown · sarif · annex4  │
 └───────────────────────────────────────────────┘
             │
             ▼
 GitHub Advanced Security / CI Pipeline / Audit Log
```

---

## 5. Quickstart

### Prerequisites

| Requirement | Version |
|---|---|
| Python | ≥ 3.11 |
| `uv` (recommended) | ≥ 0.12 |
| `pip` | ≥ 23.0 |

### Installation

```bash
# Recommended: using uv (fast, reproducible)
uv pip install aicomply-cli

# Standard pip
pip install aicomply-cli

# Development installation (includes pytest)
git clone https://github.com/aiambo08/AIComply.git
cd AIComply
uv sync --extra dev
```

### Your First Scan

```bash
# Scan any repository — results displayed in the terminal
aicomply scan ./my-ai-project

# Output findings as machine-readable JSON
aicomply scan ./my-ai-project --format json

# Output SARIF for GitHub Advanced Security
aicomply scan ./my-ai-project --format sarif --output results.sarif

# Scope scan to specific articles only (Art. 5 + Art. 12)
aicomply scan ./my-ai-project --articles 5,12

# Include SHA-256 evidence IDs in the report
aicomply scan ./my-ai-project --evidence
```

**Exit code contract:**

| Code | Meaning |
|---|---|
| `0` | Repository is fully compliant — zero findings |
| `1` | One or more compliance violations detected |
| `2` | Scanner system error (invalid path, YAML schema failure) |

### Generate an Annex IV Regulatory Dossier

```bash
aicomply docgen ./my-ai-project \
  --name "LLM-HR-Screening-Service" \
  --version "2.3.1" \
  --output ANNEX_IV_TECHNICAL_DOCS.md
```

Produces a structured Markdown document covering all 5 Annex IV sections: system identification, component inventory, monitoring status, oversight measures, and the compliance risk matrix.

### Interactive Risk Classification

```bash
aicomply assess
```

Guides stakeholders through a structured decision tree to classify a system under the EU AI Act (Prohibited / High Risk / Limited Risk / Minimal Risk), with applicable articles, enforcement timelines, and binding obligations.

---

## 6. Configuration & Advanced Usage

Create a `.aicomply.yaml` at the root of your repository to customize scanning behavior:

```yaml
# .aicomply.yaml

# Exclude paths from scanning (glob patterns)
exclude_paths:
  - "tests/**"
  - "docs/**"
  - "fixtures/**"
  - "scripts/data_generation/**"

# Disable specific rules globally (e.g., accepted risk with documented justification)
ignore_rules:
  - "EUAIA-ART15-002"   # Hardcoded secrets — managed via external secrets vault

# Enforce a maximum risk tier; scanner exits with code 1 if this tier is exceeded
enforce_risk_tier: "high_risk"

# Load additional custom rules from a local directory
custom_rules_dir: ".compliance/rules/"
```

### Inline Suppression

Add a suppression comment directly on the offending line:

```python
import fer  # aicomply:ignore EUAIA-ART05-001
requests.post(url, verify=False)  # aicomply:ignore ALL
```

---

## 7. Rule Catalog

### EU AI Act Rules

| Rule ID | Article | Title | Severity |
|---|---|---|---|
| `EUAIA-ART05-001` | Art. 5(1)(f) | Emotion inference in workplace/educational settings | CRITICAL |
| `EUAIA-ART05-002` | Art. 5(1)(c) | Social scoring algorithm | CRITICAL |
| `EUAIA-ART09-001` | Art. 9 | Absence of risk management system | MEDIUM |
| `EUAIA-ART10-001` | Art. 10 | Missing dataset governance documentation | MEDIUM |
| `EUAIA-ART11-001` | Art. 11 | Absence of Annex IV technical documentation | MEDIUM |
| `EUAIA-ART12-001` | Art. 12 | LLM calls without structured logging | HIGH |
| `EUAIA-ART13-001` | Art. 50(1) | Missing AI disclosure to end-users | HIGH |
| `EUAIA-ART14-001` | Art. 14 | Absence of human oversight override mechanism | LOW |
| `EUAIA-ART15-001` | Art. 15 | Accuracy and robustness requirements | LOW |
| `EUAIA-ART15-002` | Art. 15 | Hardcoded AI API credential (Hardcoded Secret) | CRITICAL |
| `EUAIA-ART50-002` | Art. 50 | Unmoderated LLM output delivered directly to users | MEDIUM |

### GDPR Rules

| Rule ID | Article | Title | Severity |
|---|---|---|---|
| `GDPR-ART05-001` | Art. 5(1)(a-c) | Data processing without explicit purpose limitation | MEDIUM |
| `GDPR-ART05-002` | Art. 5(1)(c) | National ID (DNI/NIE) embedded in code or static prompts | HIGH |
| `GDPR-ART05-003` | Art. 5(1)(c) | Payment card number (PAN) in source code | HIGH |
| `GDPR-ART09-001` | Art. 9 | Processing of special-category biometric/health data | HIGH |
| `GDPR-ART22-001` | Art. 22 | Fully automated decision-making without human review | HIGH |
| `GDPR-ART32-001` | Art. 32 | AI provider API key hardcoded in plain text | CRITICAL |
| `GDPR-ART32-002` | Art. 32(1)(a) | TLS/SSL verification explicitly disabled (`verify=False`) | HIGH |
| `GDPR-ART32-003` | Art. 32 | Unencrypted HTTP endpoint used for AI API calls | HIGH |

---

## 8. CI/CD Integration — GitHub Advanced Security

Add the following workflow to `.github/workflows/compliance.yml` to enforce compliance on every push and pull request:

```yaml
name: EU AI Act & GDPR Compliance Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  aicomply-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install Dependencies & AIComply
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run Test Suite
        run: pytest

      - name: Execute Deterministic Compliance Scan (SARIF)
        run: |
          aicomply scan . --format sarif --output aicomply-results.sarif || true

      - name: Upload SARIF report to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: aicomply-results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aiambo08/AIComply
    rev: v0.1.0
    hooks:
      - id: aicomply
```

---

## 9. Performance Benchmarks

| Metric | Value |
|---|---|
| Typical scan time (100-file repo) | < 50 ms |
| Regex pattern evaluation | O(n·m) with pre-compiled patterns, no per-line recompilation |
| Peak memory footprint | < 30 MB RSS |
| Finding hash computation (SHA-256) | ~0.1 ms per finding |
| Annex IV dossier generation | < 200 ms on any repo size |

---

## 10. Testing

The project ships with **47 unit and integration tests** covering all engine paths, rule catalogs, SARIF output, determinism, suppression logic, and cross-engine deduplication.

```bash
# Run the full test suite
pytest

# Run with detailed output
pytest -v --tb=short

# Run with code coverage report
pytest --cov=aicomply --cov-report=term-missing

# Run within the project virtual environment (uv)
uv run pytest
```

---

## 11. License & Legal Notice

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for full terms.

**Legal Disclaimer:** AIComply is a technical assistance and static analysis tool designed to support Compliance-by-Design engineering practices. Its output does not constitute legal advice, does not guarantee regulatory certification, and does not replace formal legal assessment by a qualified EU AI Act or GDPR legal counsel. Regulatory authority determinations remain the responsibility of the deploying organization.

---

*Built to make EU AI Act compliance a solved engineering problem, not an ongoing legal expense.*
