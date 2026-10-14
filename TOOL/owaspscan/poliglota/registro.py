"""Qual perfil analisa cada linguagem."""

from __future__ import annotations

from owaspscan.achado import Achado
from owaspscan.poliglota.detector import DetectorPoliglota
from owaspscan.poliglota.fonte import ArquivoPoliglota
from owaspscan.poliglota.javascript import PERFIL_JAVASCRIPT

PERFIS = {
    "javascript": PERFIL_JAVASCRIPT,
    "typescript": PERFIL_JAVASCRIPT,
    "tsx": PERFIL_JAVASCRIPT,
}


def detectar_poliglota(arquivo: ArquivoPoliglota) -> list[Achado]:
    """Achados de um arquivo de outra linguagem."""
    perfil = PERFIS.get(arquivo.linguagem)
    if perfil is None:
        return []
    return DetectorPoliglota(perfil).detectar(arquivo)
