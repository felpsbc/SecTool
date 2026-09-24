"""Detector de Cross-Site Request Forgery (CWE-352 -> A01:2021 Broken Access Control).

CSRF e uma defesa que o framework oferece e o codigo desliga. O detector
procura o desligamento:

1. `@csrf_exempt` / `csrf.exempt(...)` numa view — confianca alta;
2. configuracao `WTF_CSRF_ENABLED = False` — confianca alta;
3. `MIDDLEWARE` do Django listado sem `CsrfViewMiddleware` — confianca alta;
4. app Flask com rota que altera estado e nenhum `CSRFProtect` ou
   `FlaskForm` no mesmo arquivo — CANDIDATO (confianca baixa), porque a
   protecao pode ser inicializada em outro modulo (app factory).

Rotas protegidas apenas por token no cabecalho (`@jwt_required`) nao
dependem de cookie e nao sao candidatas no item 4.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import (
    CATALOGO_PADRAO,
    CONFIGURACOES_CSRF,
    DECORADORES_CSRF_EXEMPT,
    Catalogo,
    nome_pontilhado,
)
from owaspscan.motor.estrutura import (
    METODOS_QUE_ALTERAM_ESTADO,
    atribuicoes_de_configuracao,
    funcoes_de_rota,
    mapa_de_importacoes,
    metodos_http,
    nome_qualificado,
    nomes_de_decoradores,
    valor_constante,
)
from owaspscan.motor.taint import Escopo

PREFIXO_CANDIDATO = "Candidato a CSRF (requer revisao manual):"
MIDDLEWARE_CSRF_DJANGO = "django.middleware.csrf.CsrfViewMiddleware"

RECOMENDACAO = (
    "Mantenha a protecao CSRF do framework ligada: no Flask, "
    "CSRFProtect(app) do Flask-WTF; no Django, CsrfViewMiddleware e sem "
    "@csrf_exempt. Para APIs, autentique por token no cabecalho "
    "(Authorization) em vez de cookie de sessao, ou use SameSite=Strict."
)

# Autenticacao por cabecalho: o navegador nao envia sozinho, sem CSRF.
_AUTENTICACAO_POR_TOKEN = frozenset(
    {"jwt_required", "token_required", "auth_token_required", "http_auth_required"}
)


def _e_exempt(pontilhado: str) -> bool:
    ultimo = pontilhado.split(".")[-1]
    if ultimo == "csrf_exempt":
        return True
    return ultimo in DECORADORES_CSRF_EXEMPT and "csrf" in pontilhado.lower()


@dataclass(frozen=True)
class DetectorCsrf:
    """Detector de CWE-352 por desligamento da protecao do framework."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Cross-Site Request Forgery"
    cwe: str = "CWE-352"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        achados: list[Achado] = []
        achados += self._isencoes(arquivo)
        achados += self._configuracao(arquivo)
        candidato = self._app_sem_protecao(arquivo)
        if candidato is not None:
            achados.append(candidato)
        return achados

    def _isencoes(self, arquivo: ArquivoAnalisado) -> list[Achado]:
        achados: list[Achado] = []
        for no in ast.walk(arquivo.arvore):
            if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for decorador in no.decorator_list:
                    alvo = decorador.func if isinstance(decorador, ast.Call) else decorador
                    pontilhado = nome_pontilhado(alvo)
                    if pontilhado and _e_exempt(pontilhado):
                        achados.append(
                            self._montar(
                                arquivo,
                                decorador,
                                "alta",
                                f"A view {no.name} desliga a verificacao de token "
                                f"CSRF com @{pontilhado}: um site externo pode "
                                "disparar a acao com o cookie de sessao da vitima.",
                            )
                        )
            elif isinstance(no, ast.Call) and no.args:
                pontilhado = nome_pontilhado(no.func)
                if pontilhado and "." in pontilhado and _e_exempt(pontilhado):
                    achados.append(
                        self._montar(
                            arquivo,
                            no,
                            "alta",
                            f"{pontilhado}(...) isenta views da verificacao CSRF.",
                        )
                    )
        return achados

    def _configuracao(self, arquivo: ArquivoAnalisado) -> list[Achado]:
        achados: list[Achado] = []
        for atribuicao in atribuicoes_de_configuracao(arquivo.arvore):
            if (
                atribuicao.chave in CONFIGURACOES_CSRF
                and valor_constante(atribuicao.valor) is False
            ):
                achados.append(
                    self._montar(
                        arquivo,
                        atribuicao.no,
                        "alta",
                        f"{atribuicao.chave} = False desliga a protecao CSRF de "
                        "todos os formularios da aplicacao.",
                    )
                )
            elif atribuicao.chave in {"MIDDLEWARE", "MIDDLEWARE_CLASSES"}:
                itens = self._strings(atribuicao.valor)
                if (
                    itens
                    and any(i.startswith("django.") for i in itens)
                    and MIDDLEWARE_CSRF_DJANGO not in itens
                ):
                    achados.append(
                        self._montar(
                            arquivo,
                            atribuicao.no,
                            "alta",
                            f"{atribuicao.chave} do Django nao inclui "
                            f"{MIDDLEWARE_CSRF_DJANGO}: nenhuma view verifica "
                            "token CSRF.",
                        )
                    )
        return achados

    @staticmethod
    def _strings(no: ast.AST) -> list[str] | None:
        if not isinstance(no, (ast.List, ast.Tuple)):
            return None
        itens = [valor_constante(e) for e in no.elts]
        if not all(isinstance(i, str) for i in itens):
            return None  # lista montada dinamicamente: nao julgar
        return itens  # type: ignore[return-value]

    def _app_sem_protecao(self, arquivo: ArquivoAnalisado) -> Achado | None:
        importacoes = mapa_de_importacoes(arquivo.arvore)
        criacao: ast.Call | None = None
        for no in ast.walk(arquivo.arvore):
            if isinstance(no, ast.Call):
                qualificado = nome_qualificado(no.func, importacoes) or ""
                if qualificado in {"flask.Flask", "Flask"} and criacao is None:
                    criacao = no
            if isinstance(no, (ast.Name, ast.Attribute)):
                pontilhado = nome_pontilhado(no) or ""
                ultimo = pontilhado.split(".")[-1]
                if ultimo in {"CSRFProtect", "FlaskForm", "SeaSurf"}:
                    return None
        if criacao is None:
            return None
        if any(modulo.startswith("flask_wtf") for modulo in importacoes.values()):
            return None

        expostas = [
            funcao
            for funcao in funcoes_de_rota(arquivo.arvore)
            if metodos_http(funcao) & METODOS_QUE_ALTERAM_ESTADO
            and not {
                d.split(".")[-1] for d in nomes_de_decoradores(funcao)
            } & _AUTENTICACAO_POR_TOKEN
        ]
        if not expostas:
            return None
        nomes = ", ".join(f.name for f in expostas[:3])
        return self._montar(
            arquivo,
            criacao,
            "baixa",
            f"{PREFIXO_CANDIDATO} o app Flask criado aqui tem rotas que alteram "
            f"estado ({nomes}) e nenhum CSRFProtect ou FlaskForm neste arquivo. "
            "A protecao pode estar inicializada em outro modulo, por isso este "
            "achado NAO afirma vulnerabilidade.",
        )

    def _montar(
        self, arquivo: ArquivoAnalisado, no: ast.AST, confianca: str, descricao: str
    ) -> Achado:
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=self.cwe,
            severidade="media",
            confianca=confianca,
            trecho=arquivo.trecho_de(no),
            descricao=descricao,
            recomendacao=RECOMENDACAO,
        )
