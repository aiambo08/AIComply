# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-29

### Added
- **Deterministic AST Engine (`aicomply.scanner.ast_parser`)**:
  - Abstract Syntax Tree analysis leveraging Python's `ast.NodeVisitor`.
  - Multi-level alias tracking (`from openai import AsyncOpenAI as AI`, `import anthropic as ant`).
  - Class-level instance tracking and constructor argument inspection.
  - Absence detection (`ast_absence`) for missing structured logging wrappers (Art. 12).
- **High-Performance Regex Scanner (`aicomply.scanner.regex_matcher`)**:
  - Precompiled O(1) regular expression evaluation across `.py`, `.env`, `.yaml`, `.json`, `.js`, and `.ts` files.
  - Secret scanning for OpenAI, Anthropic, Cohere, and HuggingFace API credentials.
  - PII leak detection for Spanish National IDs (DNI/NIE) and Credit Card PANs (Visa, Mastercard, Amex).
- **Cross-Engine Deduplication (`aicomply.scanner.engine`)**:
  - Composite key deduplication `(rule_id, file_path, start_line)` ensuring AST findings supersede duplicate regex hits.
- **Cryptographic Evidence Engine (`aicomply.evidence.hasher`)**:
  - Deterministic SHA-256 hashing for individual findings with CRLF/LF line ending normalization.
  - Consolidated `scan_id` generated via sorted canonical finding hashes.
- **Rule Catalogs (20 Production-Ready Rules)**:
  - EU AI Act: Art. 5(1)(f) (Emotions), Art. 5(1)(c) (Social Scoring), Art. 9 (Risk Management), Art. 10 (Data Governance), Art. 11 (Technical Docs), Art. 12 (Logging), Art. 13 / Art. 50(1) (AI Transparency), Art. 14 (Human Oversight), Art. 15 (Robustness & Secrets), Art. 50(2) (Output Moderation).
  - GDPR: Art. 5(1)(c) (PII / Purpose Limitation), Art. 9 (Special Category Data), Art. 22 (Automated Profiling), Art. 32 (Secrets, Insecure TLS, Unencrypted HTTP).
- **Interactive Risk Classifier (`aicomply assess`)**:
  - Guided CLI decision tree mapping use cases to statutory risk tiers (Prohibited, High Risk, Limited Risk, Minimal Risk).
- **Annex IV Dossier Generator (`aicomply docgen`)**:
  - Automated extraction of detected AI tech stack and compilation of regulatory technical documentation.
- **Multi-Format Reporting Layer (`aicomply.reporter`)**:
  - Interactive Terminal Rich UI with risk tier badges and remediation steps.
  - Standard OASIS SARIF v2.1.0 output for GitHub Advanced Security and GitLab SAST.
  - Machine-readable JSON and formal Markdown report exports.
- **Project Configuration & Suppressions**:
  - `.aicomply.yaml` support for path exclusions, rule ignoring, and risk tier gating.
  - Inline comment suppressions via `# aicomply:ignore RULE-ID` and `ALL`.
- **Quality Assurance**:
  - Full automated test suite with 47 unit and integration tests achieving 100% pass rate.
  - GitHub Actions CI workflow with SARIF ingestion via CodeQL Action v4.

[0.1.0]: https://github.com/aiambo08/AIComply/releases/tag/v0.1.0
