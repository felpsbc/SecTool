"""Pecas compartilhadas pelos detectores baseados em taint com sinks por argumento."""

from __future__ import annotations

import ast
from typing import Iterable, Iterator

from owaspscan.motor.catalogo import SinkDeArgumento
from owaspscan.motor.estrutura import nome_qualificado
from owaspscan.motor.taint import Escopo, nos_do_escopo


def casar_sink(
    no: ast.Call, sinks: Iterable[SinkDeArgumento], importacoes: dict[str, str]
) -> SinkDeArgumento | None:
    """Sink declarado que corresponde a esta chamada, se houver."""
    qualificado = nome_qualificado(no.func, importacoes)
    if qualificado is None:
        return None
    ultimo = qualificado.split(".")[-1]
    for sink in sinks:
        if sink.qualificado and qualificado == sink.rotulo:
            return sink
        if not sink.qualificado and ultimo == sink.rotulo:
            return sink
    return None


def argumentos_do_sink(no: ast.Call, sink: SinkDeArgumento) -> list[ast.AST]:
    """Argumentos da chamada nas posicoes e palavras-chave do sink."""
    encontrados = [no.args[i] for i in sink.posicoes if i < len(no.args)]
    encontrados += [kw.value for kw in no.keywords if kw.arg in sink.palavras_chave]
    return encontrados


def testes_de_condicao(escopo: Escopo) -> Iterator[ast.AST]:
    """Expressoes usadas como condicao (if, while, assert, ternario) no escopo."""
    for no in nos_do_escopo(escopo):
        if isinstance(no, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            yield no.test


def nomes_contaminados_em(escopo: Escopo, expressao: ast.AST) -> frozenset[str]:
    """Nomes simples contaminados que aparecem dentro da expressao."""
    return frozenset(
        no.id
        for no in ast.walk(expressao)
        if isinstance(no, ast.Name) and escopo.esta_contaminado(no.id)
    )
