"""
AIComply - JSON Report Generator
Salida canónica serializada para integración en pipelines de CI/CD.
"""

from aicomply.schemas import ScanReport


def generate_json_report(report: ScanReport) -> str:
    """Genera JSON estructurado e indentado del reporte."""
    return report.model_dump_json(indent=2)