"""Detector de Cross-Site Scripting refletido (CWE-79 -> A03:2021 Injection).

Duas situacoes sao reportadas:

1. **Bypass explicito do auto-escape** — `Markup`, `mark_safe`,
   `render_template_string`: vale em qualquer contexto, porque a defesa do
   framework foi desligada de proposito sobre dado nao confiavel.
2. **HTML montado a mao numa resposta** — `make_response`, `HttpResponse`,
   `Response` ou o `return` de uma view de rota. So vale dentro de rota, e
   nao vale quando a resposta e segura: JSON, download e redirect nao sao
   HTML, e `render_template` escapa o contexto pelo proprio Jinja2.

Escape de HTML (`escape`, `bleach.clean`) neutraliza a CWE-79 e remove o
achado, conforme o catalogo de sanitizadores.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo, e_view_de_rota
from owaspscan.motor.confianca import (
    confianca_para,
    justificativa,
    procedencias_relevantes,
)
from owaspscan.motor.taint import Escopo, Procedencia, nos_do_escopo

RECOMENDACAO = (
    "Deixe o auto-escape do template fazer o trabalho: use render_template "
    "com o dado passado como variavel de contexto. Se precisar montar HTML, "
    "escape antes (markupsafe.escape / html.escape) ou sanitize com bleach."
)


def _descricao(procedencias: frozenset[Procedencia], sink: str) -> str:
    fontes = ", ".join(sorted({p.fonte for p in procedencias}))
    return (
        f"Dado nao confiavel vindo de {fontes} chega ao navegador como HTML "
        f"via {sink}, sem escape, permitindo injecao de script."
        + justificativa(procedencias)
    )


@dataclass(frozen=True)
class DetectorXss:
    """Detector de CWE-79 em codigo Flask/Django."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Cross-Site Scripting"
    cwe: str = "CWE-79"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        achados: list[Achado] = []
        for escopo in escopos:
            em_rota = e_view_de_rota(escopo.no)
            for no in nos_do_escopo(escopo):
                achado = None
                if isinstance(no, ast.Call):
                    achado = self._da_chamada(arquivo, escopo, no, em_rota)
                elif isinstance(no, ast.Return) and em_rota:
                    achado = self._do_retorno(arquivo, escopo, no)
                if achado is not None:
                    achados.append(achado)
        return achados

    def _da_chamada(
        self,
        arquivo: ArquivoAnalisado,
        escopo: Escopo,
        no: ast.Call,
        em_rota: bool,
    ) -> Achado | None:
        sink = self.catalogo.sink_xss_para(no)
        if sink is None:
            return None
        if sink.categoria == "resposta" and not em_rota:
            return None
        for argumento in self.catalogo.argumentos_de(
            no, sink.posicoes, sink.palavras_chave
        ):
            achado = self._montar(arquivo, escopo, no, argumento, sink.descricao)
            if achado is not None:
                return achado
        return None

    def _do_retorno(
        self, arquivo: ArquivoAnalisado, escopo: Escopo, no: ast.Return
    ) -> Achado | None:
        if no.value is None:
            return None
        if self.catalogo.e_resposta_segura(no.value):
            return None
        # Sinks de resposta ja sao tratados como chamada; evita achado duplo.
        if self.catalogo.sink_xss_para(no.value) is not None:
            return None
        return self._montar(
            arquivo, escopo, no, no.value, "retorno da view (servido como HTML)"
        )

    def _montar(
        self,
        arquivo: ArquivoAnalisado,
        escopo: Escopo,
        no: ast.AST,
        expressao: ast.AST,
        sink: str,
    ) -> Achado | None:
        procedencias = procedencias_relevantes(
            escopo.procedencias_da_expressao(expressao), self.cwe, self.catalogo
        )
        if not procedencias:
            return None
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=self.cwe,
            severidade="media",
            confianca=confianca_para(procedencias),
            trecho=arquivo.trecho_de(no),
            descricao=_descricao(procedencias, sink),
            recomendacao=RECOMENDACAO,
        )
