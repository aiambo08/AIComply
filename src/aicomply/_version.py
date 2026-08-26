"""
AIComply - Version Resolution
Centraliza la versión del paquete usando importlib.metadata.
Fallback a '0.1.0-dev' si el paquete no está instalado.
"""

try:
    from importlib.metadata import version
    __version__ = version("aicomply")
except Exception:
    __version__ = "0.1.0-dev"
