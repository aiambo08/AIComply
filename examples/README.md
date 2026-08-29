# AIComply Reference Examples

This directory contains production-style enterprise reference projects designed to demonstrate and validate AIComply compliance scanning.

## Available Examples

### 1. [Fintech Credit Scoring & Loan Underwriting](./fintech_credit_scoring/)
A real-world microservice simulating an AI-assisted credit scoring and automated underwriting pipeline with intentional regulatory non-compliances (EU AI Act Arts. 5, 12, 13, 14, 15, 50 and GDPR Arts. 5, 9, 22, 32).

#### Run the Scan
```bash
# Terminal report
aicomply scan examples/fintech_credit_scoring --format terminal

# Generate Annex IV technical dossier
aicomply docgen examples/fintech_credit_scoring \
  --name "Novabank-Credit-AI" \
  --version "1.0.0" \
  --output DOSSIER_ANEXO_IV.md

# Export SARIF for GitHub Advanced Security
aicomply scan examples/fintech_credit_scoring --format sarif --output results.sarif
```
