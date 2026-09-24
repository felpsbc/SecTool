"""Detector heuristico de rota sem autorizacao (CWE-862 -> A01:2021).

Como o IDOR, este detector reporta CANDIDATOS, sempre com confianca baixa:
o controle de acesso pode morar num `before_request`, num middleware ou
num decorator proprio com nome que o catalogo nao conhece.

Uma rota e candidata quando e SENSIVEL e nao mostra nenhum sinal de
controle de acesso:

- sensivel: aceita POST/PUT/PATCH/DELETE, ou esta sob `/admin`;
- sinal de acesso: decorator de autenticacao/autorizacao do catalogo, ou
  checagem no corpo (`current_user.is_admin`, `has_perm`, ...).

Para rotas de `/admin`, autenticar nao basta: `@login_required` sem papel
ou permissao continua candidato — qualquer usuario logado entraria.
Rotas publicas por natureza (login, cadastro, webhook) sao ignoradas, e um
`before_request` no arquivo suprime todas as rotas dele.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import (
    ATRIBUTOS_DE_CHECAGEM_DE_ACESSO,
    CATALOGO_PADRAO,
    DECORADORES_DE_AUTENTICACAO,
    DECORADORES_DE_AUTORIZACAO,
    PALAVRAS_DE_ROTA_PUBLICA,
    Catalogo,
)
from owaspscan.motor.estrutura import (
    METODOS_QUE_ALTERAM_ESTADO,
    caminhos_da_rota,
    funcoes_de_rota,
    metodos_http,
    nomes_de_decoradores,
    tokens_de_nome,
)
from owaspscan.motor.taint import Escopo

PREFIXO_CANDIDATO = "Candidato a rota sem autorizacao (requer revisao manual):"

RECOMENDACAO = (
    "Declare o controle de acesso na propria rota: @login_required para "
    "acoes de usuario e um decorator de papel/permissao (@roles_required, "
    "@permission_required) para rotas administrativas. Negue por padrao."
)

_HOOKS_GLOBAIS = frozenset({"before_request", "before_app_request"})
# Checagens que so provam autenticacao, insuficientes em rota de /admin.
_SO_AUTENTICACAO = frozenset({"is_authenticated", "is_anonymous"})


def _e_rota_publica(funcao: ast.AST, caminhos: list[str]) -> bool:
    palavras = set(tokens_de_nome(funcao.name))
    for caminho in caminhos:
        for segmento in caminho.split("/"):
            palavras.update(tokens_de_nome(segmento))
    return bool(palavras & PALAVRAS_DE_ROTA_PUBLICA)


def _e_administrativa(funcao: ast.AST, caminhos: list[str]) -> bool:
    if "admin" in tokens_de_nome(funcao.name):
        return True
    return any("admin" in c.lower().split("/") for c in caminhos)


def _checagens_no_corpo(funcao: ast.AST) -> set[str]:
    return {
        no.attr
        for no in ast.walk(funcao)
        if isinstance(no, ast.Attribute) and no.attr in ATRIBUTOS_DE_CHECAGEM_DE_ACESSO
    }


@dataclass(frozen=True)
class DetectorAutorizacao:
    """Detector heuristico de CWE-862. Reporta candidatos."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Missing Authorization"
    cwe: str = "CWE-862"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        if self._tem_hook_global(arquivo.arvore):
            return []
        achados: list[Achado] = []
        for funcao in funcoes_de_rota(arquivo.arvore):
            motivo = self._motivo(funcao)
            if motivo is not None:
                achados.append(self._montar(arquivo, funcao, motivo))
        return achados

    @staticmethod
    def _tem_hook_global(arvore: ast.AST) -> bool:
        for no in ast.walk(arvore):
            if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if {d.split(".")[-1] for d in nomes_de_decoradores(no)} & _HOOKS_GLOBAIS:
                    return True
        return False

    def _motivo(self, funcao: ast.AST) -> str | None:
        caminhos = caminhos_da_rota(funcao)
        if _e_rota_publica(funcao, caminhos):
            return None
        decoradores = {d.split(".")[-1] for d in nomes_de_decoradores(funcao)}
        autoriza = bool(decoradores & DECORADORES_DE_AUTORIZACAO)
        autentica = bool(decoradores & DECORADORES_DE_AUTENTICACAO)
        checagens = _checagens_no_corpo(funcao)

        if _e_administrativa(funcao, caminhos):
            if autoriza or checagens - _SO_AUTENTICACAO:
                return None
            if autentica:
                return (
                    "rota administrativa exige apenas autenticacao; qualquer "
                    "usuario logado a alcanca sem checagem de papel ou permissao"
                )
            return "rota administrativa sem nenhum controle de acesso visivel"

        metodos = metodos_http(funcao) & METODOS_QUE_ALTERAM_ESTADO
        if metodos and not (autoriza or autentica or checagens):
            return (
                f"rota que altera estado ({', '.join(sorted(metodos))}) sem "
                "autenticacao nem autorizacao visiveis"
            )
        return None

    def _montar(self, arquivo: ArquivoAnalisado, funcao: ast.AST, motivo: str) -> Achado:
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=funcao.lineno,
            cwe=self.cwe,
            severidade="media",
            # Heuristica: confianca sempre baixa, por decisao de projeto.
            confianca="baixa",
            trecho=f"def {funcao.name}(...)",
            descricao=(
                f"{PREFIXO_CANDIDATO} {motivo}. O controle pode existir fora do "
                "escopo analisado (middleware, blueprint, decorator proprio), por "
                "isso este achado NAO afirma vulnerabilidade."
            ),
            recomendacao=RECOMENDACAO,
        )
