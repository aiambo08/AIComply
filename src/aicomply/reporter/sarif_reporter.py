"""
AIComply - SARIF v2.1.0 Report Generator
Emite resultados de análisis estático compatibles con Github Code Scanning
"""

import json
from typing import Any, Dict
from aicomply.schemas import ScanReport, Severity

# Mapeo de severidad AIComply -> Nivel SARIF
SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

def generate_sarif_report(report: ScanReport) -> str:
    """Convierte un ScanReport en un documento JSON SARIF v2.1.0 válido."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results = []

    for f in report.findings:
        # Registrar metadatos de la regla en el diccionario SARIF si no existe
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "helpUri": f"https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                "properties": {
                    "article": f.article,
                    "risk_tier": f.risk_tier.value,
                    "max_fine": f.max_fine,
                    "remediation": f.remediation,
                },
            }

        # Construir el resultado individual del hallazgo
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL_MAP.get(f.severity, "warning"),
            "message": {
                "text": f"[{f.article}] {f.title}. Multa potencial: {f.max_fine}. Remediación: {f.remediation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.file_path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": f.location.start_line,
                            "endLine": f.location.end_line,
                            "startColumn": max(1, f.location.start_col + 1),
                            "endColumn": max(1, f.location.end_col + 1),
                            "snippet": {"text": f.code_snippet or ""}
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "sha256": f.id
            }
        })

    sarif_payload = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIComply",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/aibo-ni/aicomply",
                        "rules": list(rules_dict.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.timestamp,
                    }
                ],
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_payload, indent=2)