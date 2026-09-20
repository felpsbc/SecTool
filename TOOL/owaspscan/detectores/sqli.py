"""Detector de SQL Injection (CWE-89 -> A03:2021 Injection).

Reporta quando dado de fonte nao confiavel alcanca a string SQL de um sink
DB-API. O argumento de parametros nao e inspecionado: parametrizar e a
defesa correta, e acusar ali seria falso positivo.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo
from owaspscan.motor.confianca import (
    confianca_para,
    justificativa,
    procedencias_relevantes,
)
from owaspscan.motor.taint import Escopo, Procedencia, nos_do_escopo

RECOMENDACAO = (
    "Use query parametrizada, delegando a interpolacao ao driver: "
    "cursor.execute('... WHERE id = ?', (valor,)). Nunca monte SQL com "
    "concatenacao, %, .format() ou f-string sobre dado da requisicao."
)


def _descricao(procedencias: frozenset[Procedencia], sink: str) -> str:
    fontes = ", ".join(sorted({p.fonte for p in procedencias}))
    return (
        f"Dado nao confiavel vindo de {fontes} alcanca a string SQL de "
        f"{sink} sem parametrizacao, permitindo alterar a estrutura da query."
        + justificativa(procedencias)
    )


@dataclass(frozen=True)
class DetectorSqlInjection:
    """Detector de CWE-89 sobre sinks DB-API 2.0."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "SQL Injection"
    cwe: str = "CWE-89"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        achados: list[Achado] = []
        for escopo in escopos:
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                sink = self.catalogo.sink_sql_para(no)
                if sink is None:
                    continue
                for argumento in self.catalogo.argumentos_de_sql(no, sink):
                    procedencias = procedencias_relevantes(
                        escopo.procedencias_da_expressao(argumento),
                        self.cwe,
                        self.catalogo,
                    )
                    if not procedencias:
                        continue
                    achados.append(
                        criar_achado(
                            arquivo=arquivo.arquivo,
                            linha=arquivo.linha_de(no),
                            cwe=self.cwe,
                            severidade="alta",
                            confianca=confianca_para(procedencias),
                            trecho=arquivo.trecho_de(no),
                            descricao=_descricao(procedencias, sink.descricao),
                            recomendacao=RECOMENDACAO,
                        )
                    )
                    break  # um achado por chamada, mesmo com varios argumentos
        return achados
