"""Detector generico: aplica os sinks do perfil sobre os escopos analisados.

Um so detector cobre as CWEs de injecao (89, 79, 22, 601) e as credenciais
fixas (798) de qualquer linguagem com perfil. A classificacao OWASP continua
vindo exclusivamente de `criar_achado`.
"""

from __future__ import annotations

from owaspscan.achado import Achado, criar_achado
from owaspscan.motor.confianca import confianca_para, justificativa
from owaspscan.motor.credenciais import (
    e_segredo_plausivel,
    mascarar,
    nomeia_credencial,
    url_com_senha,
)
from owaspscan.motor.taint import Procedencia
from owaspscan.poliglota.fonte import ArquivoPoliglota
from owaspscan.poliglota.motor import EscopoPoliglota, analisar_taint_poliglota
from owaspscan.poliglota.perfil import Perfil, Sink, casa_algum

SEVERIDADE: dict[str, str] = {
    "CWE-89": "alta",
    "CWE-79": "media",
    "CWE-22": "alta",
    "CWE-601": "media",
    "CWE-798": "alta",
}

CONSEQUENCIA: dict[str, str] = {
    "CWE-89": "sem parametrizacao, permitindo alterar a estrutura da query.",
    "CWE-79": "sem escape, permitindo injecao de script no navegador.",
    "CWE-22": "sem confinamento, permitindo acessar arquivos fora do "
    "diretorio esperado com '../'.",
    "CWE-601": "sem validacao do destino, permitindo redirecionar o usuario "
    "para um site arbitrario (phishing).",
}

# Guardas (`if (!destino.startsWith("/"))`) nao sao interpretadas pelo motor;
# quando existem, o achado cai para confianca media em vez de sumir.
CWES_COM_GUARDA = frozenset({"CWE-22", "CWE-601"})

SINK_DE_SAIDA_HTML = Sink(cwe="CWE-79", padroes=(), descricao="a saida HTML da pagina")


def _relevantes(
    procedencias: frozenset[Procedencia], cwe: str, perfil: Perfil
) -> frozenset[Procedencia]:
    return frozenset(
        p for p in procedencias if not perfil.neutraliza(p.sanitizadores, cwe)
    )


def _guardado(escopo: EscopoPoliglota, expressoes) -> bool:
    citados: frozenset[str] = frozenset()
    for expressao in expressoes:
        citados |= escopo.nomes_contaminados_em(expressao)
    if not citados:
        return False
    for no in escopo.nos:
        if no.type in escopo.perfil.condicoes:
            condicao = no.child_by_field_name("condition") or no
            if escopo.nomes_contaminados_em(condicao) & citados:
                return True
    return False


def _argumentos(argumentos, sink: Sink) -> tuple:
    if sink.argumentos is None:
        return tuple(argumentos)
    return tuple(argumentos[i] for i in sink.argumentos if i < len(argumentos))


class DetectorPoliglota:
    """Taint (CWE-89/79/22/601) e credenciais fixas (CWE-798) via perfil."""

    def __init__(self, perfil: Perfil) -> None:
        self.perfil = perfil

    def detectar(self, arquivo: ArquivoPoliglota) -> list[Achado]:
        escopos = analisar_taint_poliglota(arquivo, self.perfil)
        achados: dict[tuple[int, str], Achado] = {}
        for escopo in escopos:
            for no in escopo.nos:
                for chave, achado in self._injecoes(arquivo, escopo, no):
                    achados.setdefault(chave, achado)
                for chave, achado in self._credenciais(arquivo, no):
                    achados.setdefault(chave, achado)
        return list(achados.values())

    # -- injecao -----------------------------------------------------------

    def _injecoes(self, arquivo, escopo, no):
        perfil = self.perfil
        chamada = perfil.chamada(no)
        if chamada is not None:
            for sink in perfil.sinks:
                if sink.atribuicao or casa_algum(sink.padroes, chamada.nome) is None:
                    continue
                expressoes = _argumentos(chamada.argumentos, sink)
                achado = self._avaliar(arquivo, escopo, no, sink, expressoes, chamada.nome)
                if achado is not None:
                    yield (no.id, sink.cwe), achado

        atribuicao = perfil.atribuicao(no)
        if atribuicao is not None and atribuicao.alvo is not None:
            for sink in perfil.sinks:
                if not sink.atribuicao:
                    continue
                alvo = next(
                    (a for a in atribuicao.alvos if casa_algum(sink.padroes, a)), None
                )
                if alvo is None:
                    continue
                achado = self._avaliar(
                    arquivo, escopo, no, sink, (atribuicao.valor,), alvo
                )
                if achado is not None:
                    yield (no.id, sink.cwe), achado

        saidas = perfil.saidas_html(no)
        if saidas:
            achado = self._avaliar(arquivo, escopo, no, SINK_DE_SAIDA_HTML, saidas, None)
            if achado is not None:
                yield (no.id, "CWE-79"), achado

    def _avaliar(self, arquivo, escopo, no, sink: Sink, expressoes, nome) -> Achado | None:
        procedencias: frozenset[Procedencia] = frozenset()
        for expressao in expressoes:
            procedencias |= escopo.procedencias_da_expressao(expressao)
        procedencias = _relevantes(procedencias, sink.cwe, self.perfil)
        if not procedencias:
            return None

        confianca = confianca_para(procedencias)
        motivo = justificativa(procedencias)
        if sink.cwe in CWES_COM_GUARDA and _guardado(escopo, expressoes):
            confianca = "media"
            motivo += (
                " Ha verificacao condicional sobre o dado que o motor nao "
                "interpreta; confirme se ela de fato restringe o valor."
            )

        fontes = ", ".join(sorted({p.fonte for p in procedencias}))
        descricao = sink.descricao.format(nome=nome) if nome else sink.descricao
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=sink.cwe,
            severidade=SEVERIDADE[sink.cwe],
            confianca=confianca,
            trecho=arquivo.trecho_de(no),
            descricao=(
                f"Dado nao confiavel vindo de {fontes} alcanca {descricao} "
                + CONSEQUENCIA[sink.cwe]
                + motivo
            ),
            recomendacao=self.perfil.recomendacoes[sink.cwe],
        )

    # -- credenciais -------------------------------------------------------

    def _credenciais(self, arquivo, no):
        perfil = self.perfil
        candidatos: list[tuple[str, object]] = []
        atribuicao = perfil.atribuicao(no)
        if atribuicao is not None:
            candidatos += [(alvo.split(".")[-1], atribuicao.valor) for alvo in atribuicao.alvos]
        par = perfil.pares_de_credencial(no)
        if par is not None:
            candidatos.append(par)

        for nome, valor in candidatos:
            segredo = perfil.texto_literal(valor)
            if segredo is None or not nomeia_credencial(nome) or not e_segredo_plausivel(segredo):
                continue
            yield (valor.id, "CWE-798"), self._achado_de_credencial(
                arquivo, no, segredo,
                f"Credencial fixa no codigo: literal atribuido a '{nome}'.",
            )
            return

        segredo = perfil.texto_literal(no)
        esquema = url_com_senha(segredo) if segredo is not None else None
        if esquema is not None:
            yield (no.id, "CWE-798"), self._achado_de_credencial(
                arquivo, no, segredo,
                f"URL de conexao ({esquema}) com senha embutida no codigo.",
            )

    def _achado_de_credencial(self, arquivo, no, segredo: str, motivo: str) -> Achado:
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe="CWE-798",
            severidade=SEVERIDADE["CWE-798"],
            confianca="alta",
            trecho=mascarar(arquivo.trecho_de(no), segredo),
            descricao=(
                motivo + " Qualquer pessoa com acesso ao repositorio (ou ao "
                "bundle publicado, no caso de front-end) passa a ter o segredo."
            ),
            recomendacao=self.perfil.recomendacoes["CWE-798"],
        )
