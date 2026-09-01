"""
AIComply - SARIF v2.1.0 Report Generator
Emite resultados de análisis estático compatibles con Github Code Scanning
"""

import json
from typing import Any, Dict
from aicomply.schemas import ScanReport, Severity
from aicomply._version import __version__

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

        # Calcular ruleIndex: posición de la regla en el array rules_dict
        rule_index = list(rules_dict.keys()).index(f.rule_id)

        # Construir el resultado individual del hallazgo
        result_item: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index,
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
        }

        # Exportar traza de flujo de datos interactiva (codeFlows) si está presente
        if f.flow_steps:
            thread_flow_locs = []
            for step in f.flow_steps:
                thread_flow_locs.append({
                    "location": {
                        "message": {"text": f"{step.step_type.upper()}: {step.message}"},
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": step.location.file_path.replace("\\", "/")
                            },
                            "region": {
                                "startLine": step.location.start_line,
                                "endLine": step.location.end_line,
                                "startColumn": max(1, step.location.start_col + 1),
                                "endColumn": max(1, step.location.end_col + 1),
                                "snippet": {"text": step.code_snippet or ""}
                            }
                        }
                    },
                    "nestingLevel": 0
                })
            result_item["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": thread_flow_locs
                        }
                    ]
                }
            ]

        results.append(result_item)

    sarif_payload = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIComply",
                        "version": __version__,
                        "informationUri": "https://github.com/aiambo08/AIComply",
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