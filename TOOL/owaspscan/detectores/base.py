"""Interface comum dos detectores.

Um detector nao anda na AST por conta propria nem decide classificacao:
recebe os escopos ja analisados pelo motor de taint e devolve achados
construidos por `criar_achado`, que impoe o mapa CWE -> OWASP.
"""

from __future__ import annotations

from typing import Protocol

from owaspscan.achado import Achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.taint import Escopo


class Detector(Protocol):
    """Contrato que todo detector implementa."""

    nome: str
    cwe: str

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]: ...


def ordenar_achados(achados: list[Achado]) -> list[Achado]:
    """Ordem estavel de relatorio: arquivo, linha, CWE."""
    return sorted(achados, key=lambda a: (a.arquivo, a.linha, a.cwe))
