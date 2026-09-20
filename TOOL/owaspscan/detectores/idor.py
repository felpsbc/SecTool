"""Detector heuristico de IDOR (CWE-639 -> A01:2021 Broken Access Control).

Diferente de SQLi e XSS, este detector NAO afirma vulnerabilidade: ele
reporta CANDIDATOS para revisao manual, sempre com `confianca="baixa"`.

O padrao procurado e a assinatura classica do IDOR: um identificador vindo
da requisicao (parametro de rota ou query string) usado para recuperar um
objeto do banco, sem que a consulta amarre o objeto ao usuario autenticado.

Nao e possivel decidir estaticamente se existe controle de acesso: ele pode
estar num decorator personalizado, num middleware, num metodo do modelo ou
na camada de servico. Por isso o achado nasce como candidato, e dois sinais
o suprimem: filtro por dono na propria consulta e decorator de autorizacao
na view. `@login_required` nao suprime — autenticar nao e autorizar.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import (
    CAMPOS_DE_DONO,
    CATALOGO_PADRAO,
    Catalogo,
    tem_decorador_de_autorizacao,
)
from owaspscan.motor.confianca import procedencias_relevantes
from owaspscan.motor.taint import (
    Escopo,
    Procedencia,
    literais_de_string,
    nos_do_escopo,
)

PREFIXO_CANDIDATO = "Candidato a IDOR (requer revisao manual):"

RECOMENDACAO = (
    "Confirme manualmente se o objeto pertence ao usuario autenticado. "
    "Prefira amarrar a consulta ao dono — Pedido.query.filter_by(id=pid, "
    "user=current_user) — em vez de checar depois de recuperar o objeto. "
    "Autenticacao (@login_required) nao substitui autorizacao."
)

# Termos que indicam filtro por identificador dentro de uma consulta SQL.
_TERMOS_DE_ID = ("id =", "id=", "id_", "_id", ".id", " id ")


def _compara_campo_de_dono(texto: str) -> bool:
    """A consulta COMPARA um campo de dono, e nao apenas o menciona?

    Exigir o operador evita supressao acidental: uma tabela chamada
    `usuarios` nao pode contar como filtro por dono.
    """
    return any(
        f"{campo} =" in texto or f"{campo}=" in texto for campo in CAMPOS_DE_DONO
    )


@dataclass(frozen=True)
class DetectorIdor:
    """Detector heuristico de CWE-639. Reporta candidatos, nao vulnerabilidades."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "IDOR"
    cwe: str = "CWE-639"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        achados: list[Achado] = []
        for escopo in escopos:
            if tem_decorador_de_autorizacao(escopo.no):
                continue
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                achado = self._do_lookup(arquivo, escopo, no) or self._da_consulta_sql(
                    arquivo, escopo, no
                )
                if achado is not None:
                    achados.append(achado)
        return achados

    def _do_lookup(
        self, arquivo: ArquivoAnalisado, escopo: Escopo, no: ast.Call
    ) -> Achado | None:
        lookup = self.catalogo.lookup_de_objeto(no)
        if lookup is None:
            return None
        if self.catalogo.tem_filtro_de_dono(no):
            return None
        for argumento in self.catalogo.argumentos_de_identificador(no, lookup):
            procedencias = self._procedencias(escopo, argumento)
            if procedencias:
                return self._montar(arquivo, escopo, no, procedencias, lookup)
        return None

    def _da_consulta_sql(
        self, arquivo: ArquivoAnalisado, escopo: Escopo, no: ast.Call
    ) -> Achado | None:
        sink = self.catalogo.sink_sql_para(no)
        if sink is None:
            return None
        argumentos = self.catalogo.argumentos_de_sql(no, sink)
        if not argumentos:
            return None
        texto = literais_de_string(escopo, argumentos[0]).lower()
        if "where" not in texto or not any(termo in texto for termo in _TERMOS_DE_ID):
            return None
        if _compara_campo_de_dono(texto):
            return None
        for argumento in no.args:
            procedencias = self._procedencias(escopo, argumento)
            if procedencias:
                return self._montar(
                    arquivo,
                    escopo,
                    no,
                    procedencias,
                    "consulta SQL filtrada por identificador",
                )
        return None

    def _procedencias(
        self, escopo: Escopo, expressao: ast.AST
    ) -> frozenset[Procedencia]:
        return procedencias_relevantes(
            escopo.procedencias_da_expressao(expressao), self.cwe, self.catalogo
        )

    def _montar(
        self,
        arquivo: ArquivoAnalisado,
        escopo: Escopo,
        no: ast.AST,
        procedencias: frozenset[Procedencia],
        lookup: str,
    ) -> Achado:
        fontes = ", ".join(sorted({p.fonte for p in procedencias}))
        descricao = (
            f"{PREFIXO_CANDIDATO} identificador vindo de {fontes} e usado em "
            f"{lookup} sem filtro pelo usuario autenticado na propria consulta. "
            "O controle de acesso pode existir fora do escopo analisado "
            "(middleware, decorator proprio, camada de servico), por isso este "
            "achado NAO afirma vulnerabilidade."
        )
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=self.cwe,
            severidade="media",
            # Heuristica: confianca sempre baixa, por decisao de projeto.
            confianca="baixa",
            trecho=arquivo.trecho_de(no),
            descricao=descricao,
            recomendacao=RECOMENDACAO,
        )
