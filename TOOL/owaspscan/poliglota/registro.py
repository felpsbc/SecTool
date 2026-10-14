"""Qual perfil analisa cada linguagem."""

from __future__ import annotations

from owaspscan.achado import Achado
from owaspscan.poliglota.detector import DetectorPoliglota
from owaspscan.poliglota.fonte import ArquivoPoliglota
from owaspscan.poliglota.html import detectar_html
from owaspscan.poliglota.java import PERFIL_JAVA
from owaspscan.poliglota.javascript import PERFIL_JAVASCRIPT
from owaspscan.poliglota.php import PERFIL_PHP

PERFIS = {
    "javascript": PERFIL_JAVASCRIPT,
    "typescript": PERFIL_JAVASCRIPT,
    "tsx": PERFIL_JAVASCRIPT,
    "java": PERFIL_JAVA,
    "php": PERFIL_PHP,
}


def detectar_poliglota(arquivo: ArquivoPoliglota) -> list[Achado]:
    """Achados de um arquivo de outra linguagem."""
    if arquivo.linguagem == "html":
        return detectar_html(arquivo)
    perfil = PERFIS.get(arquivo.linguagem)
    if perfil is None:
        return []
    return DetectorPoliglota(perfil).detectar(arquivo)
