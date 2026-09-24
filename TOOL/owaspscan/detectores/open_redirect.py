"""Detector de Open Redirect (CWE-601 -> A01:2021 Broken Access Control).

Reporta quando dado de fonte nao confiavel vira o destino de um redirect
(`redirect`, `HttpResponseRedirect`, `RedirectResponse`). O padrao classico
de codigo gerado por IA e `redirect(request.args.get("next") or "/")`.

Removem o achado:

1. `url_for` / `reverse`, que produzem URL interna (sanitizadores de CWE-601
   no catalogo);
2. validacao do destino numa condicao — `url_has_allowed_host_and_scheme`,
   `is_safe_url` ou checagem de `urlparse(destino).netloc`.

`destino.startswith("/")` NAO conta como validacao: `//site-malicioso.com`
comeca com barra e e tratado pelo navegador como outro host.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.detectores.comum import (
    argumentos_do_sink,
    casar_sink,
    nomes_contaminados_em,
    testes_de_condicao,
)
from owaspscan.motor.catalogo import (
    CATALOGO_PADRAO,
    SINKS_DE_REDIRECT,
    VALIDADORES_DE_REDIRECT,
    Catalogo,
    nome_pontilhado,
)
from owaspscan.motor.confianca import (
    confianca_para,
    justificativa,
    procedencias_relevantes,
)
from owaspscan.motor.estrutura import mapa_de_importacoes
from owaspscan.motor.taint import Escopo, Procedencia, nos_do_escopo

RECOMENDACAO = (
    "Redirecione para rotas internas com url_for/reverse. Se o destino vier "
    "da requisicao (parametro next), valide com "
    "url_has_allowed_host_and_scheme (Django) ou confira que "
    "urlparse(destino).netloc esta vazio ou numa lista de hosts permitidos."
)

_PARSERS_DE_URL = frozenset({"urlparse", "urlsplit"})


def nomes_validados(escopo: Escopo) -> frozenset[str]:
    """Nomes contaminados cujo destino e validado numa condicao."""
    validados: set[str] = set()
    for teste in testes_de_condicao(escopo):
        for no in ast.walk(teste):
            if isinstance(no, ast.Call):
                pontilhado = nome_pontilhado(no.func)
                if pontilhado and pontilhado.split(".")[-1] in VALIDADORES_DE_REDIRECT:
                    for arg in [*no.args, *(kw.value for kw in no.keywords)]:
                        validados |= nomes_contaminados_em(escopo, arg)
            elif (
                isinstance(no, ast.Attribute)
                and no.attr == "netloc"
                and isinstance(no.value, ast.Call)
                and (pontilhado := nome_pontilhado(no.value.func))
                and pontilhado.split(".")[-1] in _PARSERS_DE_URL
            ):
                for arg in no.value.args:
                    validados |= nomes_contaminados_em(escopo, arg)
    return frozenset(validados)


@dataclass(frozen=True)
class DetectorOpenRedirect:
    """Detector de CWE-601 sobre respostas de redirecionamento."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Open Redirect"
    cwe: str = "CWE-601"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        importacoes = mapa_de_importacoes(arquivo.arvore)
        achados: list[Achado] = []
        for escopo in escopos:
            validados = nomes_validados(escopo)
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                sink = casar_sink(no, SINKS_DE_REDIRECT, importacoes)
                if sink is None:
                    continue
                for destino in argumentos_do_sink(no, sink):
                    procedencias = procedencias_relevantes(
                        escopo.procedencias_da_expressao(destino),
                        self.cwe,
                        self.catalogo,
                    )
                    if not procedencias:
                        continue
                    usados = nomes_contaminados_em(escopo, destino)
                    if usados and usados <= validados:
                        continue
                    achados.append(
                        self._montar(arquivo, no, procedencias, sink.descricao)
                    )
                    break
        return achados

    def _montar(
        self,
        arquivo: ArquivoAnalisado,
        no: ast.AST,
        procedencias: frozenset[Procedencia],
        sink: str,
    ) -> Achado:
        fontes = ", ".join(sorted({p.fonte for p in procedencias}))
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=self.cwe,
            severidade="media",
            confianca=confianca_para(procedencias),
            trecho=arquivo.trecho_de(no),
            descricao=(
                f"Destino de {sink} vem de {fontes} sem validacao de host, "
                "permitindo enviar o usuario a um site do atacante com um link "
                "que parece legitimo (phishing)."
                + justificativa(procedencias)
            ),
            recomendacao=RECOMENDACAO,
        )
