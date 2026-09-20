"""Calibracao de confianca a partir da procedencia do taint.

O campo `confianca` do achado precisa carregar informacao real, nao repetir
a CWE. Ele descreve quanto o motor confia na cadeia fonte -> sink:

  alta  — a fonte alcanca o sink por operacoes de string diretas, em fluxo
          incondicional dentro do escopo;
  media — a cadeia passou por funcao nao analisada ou por ramo condicional,
          entao o motor nao viu o caminho inteiro.

Sanitizacao nao rebaixa confianca: ela remove o achado, quando neutraliza a
CWE em questao (ver `procedencias_relevantes`).
"""

from __future__ import annotations

from owaspscan.motor.catalogo import Catalogo
from owaspscan.motor.taint import Procedencia


def procedencias_relevantes(
    procedencias: frozenset[Procedencia], cwe: str, catalogo: Catalogo
) -> frozenset[Procedencia]:
    """Descarta as cadeias cuja sanitizacao neutraliza esta CWE."""
    return frozenset(
        p
        for p in procedencias
        if not catalogo.neutraliza(p.sanitizadores, cwe)
    )


def confianca_para(procedencias: frozenset[Procedencia]) -> str:
    """Confianca do achado, dada a melhor cadeia que o sustenta."""
    if any(not p.via_chamada and not p.condicional for p in procedencias):
        return "alta"
    return "media"


def justificativa(procedencias: frozenset[Procedencia]) -> str:
    """Frase curta explicando por que a confianca nao e alta."""
    if confianca_para(procedencias) == "alta":
        return ""
    motivos = []
    if any(p.via_chamada for p in procedencias):
        motivos.append("o dado passa por funcao nao analisada")
    if any(p.condicional for p in procedencias):
        motivos.append("a contaminacao ocorre em ramo condicional")
    return " Confianca reduzida porque " + " e ".join(motivos) + "."
