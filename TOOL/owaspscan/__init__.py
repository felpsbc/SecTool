"""OWASP-Scan: analisador estatico de vulnerabilidades em codigo Python."""

from owaspscan.achado import (
    MAPA_CWE_OWASP,
    Achado,
    criar_achado,
)
from owaspscan.varredura import VERSAO, Varredura, executar

__all__ = [
    "Achado",
    "criar_achado",
    "MAPA_CWE_OWASP",
    "Varredura",
    "executar",
]
__version__ = VERSAO
