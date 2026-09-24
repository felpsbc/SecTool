"""Resumo executivo dos achados: saida em texto e em JSON.

Este modulo e puro: recebe uma `Varredura` ja pronta e formata. Nao le
arquivos nem executa detectores, o que mantem a saida deterministica e
testavel sem tocar em disco.

Achados rastreados por taint e candidatos heuristicos aparecem em secoes
separadas. O corte e `confianca == "baixa"`, nao a CWE: qualquer detector
heuristico futuro cai na secao certa sem mudar este modulo.

`Varredura` e definida em `varredura.py` e reexportada aqui por
conveniencia de importacao.
"""

from __future__ import annotations

import textwrap
from collections import Counter
from dataclasses import dataclass


from owaspscan.achado import Achado
from owaspscan.varredura import CONFIANCA_DE_CANDIDATO, Varredura

LARGURA = 74
ORDEM_SEVERIDADE = {"alta": 0, "media": 1, "baixa": 2}
ORDEM_CONFIANCA = {"alta": 0, "media": 1, "baixa": 2}


@dataclass(frozen=True)
class Resumo:
    """Contagens agregadas de uma varredura."""

    total: int
    confirmados: int
    candidatos: int
    por_severidade: dict[str, int]
    por_owasp: dict[str, int]
    por_cwe: dict[str, int]
    por_arquivo: dict[str, int]
    arquivos_com_achado: int


def _contar(valores) -> dict[str, int]:
    """Contagem ordenada por frequencia decrescente e depois por nome."""
    contagem = Counter(valores)
    return dict(sorted(contagem.items(), key=lambda par: (-par[1], par[0])))


def ordenar(achados) -> list[Achado]:
    """Ordem de leitura: severidade, confianca, arquivo, linha, CWE."""
    return sorted(
        achados,
        key=lambda a: (
            ORDEM_SEVERIDADE.get(a.severidade, 9),
            ORDEM_CONFIANCA.get(a.confianca, 9),
            a.arquivo,
            a.linha,
            a.cwe,
        ),
    )


def resumir(varredura: Varredura) -> Resumo:
    """Agrega as contagens que abrem o relatorio."""
    achados = varredura.achados
    return Resumo(
        total=len(achados),
        confirmados=len(varredura.confirmados),
        candidatos=len(varredura.candidatos),
        por_severidade=_contar(a.severidade for a in achados),
        por_owasp=_contar(a.owasp for a in achados),
        por_cwe=_contar(a.cwe for a in achados),
        por_arquivo=_contar(a.arquivo for a in achados),
        arquivos_com_achado=len({a.arquivo for a in achados}),
    )


def _linha_de_contagem(contagem: dict[str, int]) -> str:
    if not contagem:
        return "nenhum"
    return " | ".join(f"{chave} {valor}" for chave, valor in contagem.items())


def _texto_recuado(texto: str, recuo: str = "    ") -> list[str]:
    """Quebra o texto na largura do relatorio, preservando o recuo."""
    return textwrap.wrap(
        texto, width=LARGURA - len(recuo), initial_indent=recuo, subsequent_indent=recuo
    )


def _bloco_de_achado(achado: Achado) -> list[str]:
    return [
        f"  [{achado.severidade.upper()} / confianca {achado.confianca}] "
        f"{achado.cwe} {achado.vulnerabilidade}",
        f"    {achado.arquivo}:{achado.linha}  ({achado.owasp})",
        f"    > {achado.trecho}",
        *_texto_recuado(achado.descricao),
        "",
    ]


def formatar_texto(varredura: Varredura) -> str:
    """Resumo executivo legivel no terminal."""
    resumo = resumir(varredura)
    regua = "=" * LARGURA
    divisor = "-" * LARGURA
    linhas = [
        regua,
        f" OWASP-Scan v{varredura.versao} — resumo executivo",
        regua,
        f" Raiz analisada : {varredura.raiz}",
        f" Data/hora      : {varredura.momento.strftime('%Y-%m-%d %H:%M:%S')}",
        f" Arquivos       : {varredura.arquivos_analisados} analisados, "
        f"{varredura.arquivos_de_configuracao} de configuracao, "
        f"{len(varredura.falhas)} com falha de leitura",
        f" Achados        : {resumo.total} "
        f"({resumo.confirmados} rastreados por taint, "
        f"{resumo.candidatos} candidatos heuristicos) "
        f"em {resumo.arquivos_com_achado} arquivo(s)",
        f" Severidade     : {_linha_de_contagem(resumo.por_severidade)}",
        f" OWASP Top 10   : {_linha_de_contagem(resumo.por_owasp)}",
        "",
    ]

    linhas += [divisor, " ACHADOS RASTREADOS POR TAINT", divisor, ""]
    if varredura.confirmados:
        for achado in ordenar(varredura.confirmados):
            linhas += _bloco_de_achado(achado)
    else:
        linhas += ["  Nenhum achado rastreado por taint.", ""]

    linhas += [
        divisor,
        " CANDIDATOS HEURISTICOS (requerem revisao manual)",
        divisor,
        "",
    ]
    if varredura.candidatos:
        linhas += [
            "  Estes itens NAO afirmam vulnerabilidade: sao padroes suspeitos",
            "  cuja confirmacao depende de contexto que a analise estatica nao ve.",
            "",
        ]
        for achado in ordenar(varredura.candidatos):
            linhas += _bloco_de_achado(achado)
    else:
        linhas += ["  Nenhum candidato heuristico.", ""]

    recomendacoes = {a.cwe: (a.vulnerabilidade, a.recomendacao) for a in ordenar(varredura.achados)}
    if recomendacoes:
        linhas += [divisor, " RECOMENDACOES POR TIPO", divisor, ""]
        for cwe, (vulnerabilidade, recomendacao) in sorted(recomendacoes.items()):
            linhas += [f"  {cwe} {vulnerabilidade}", *_texto_recuado(recomendacao), ""]

    if varredura.falhas:
        linhas += [divisor, " ARQUIVOS NAO ANALISADOS", divisor, ""]
        for falha in varredura.falhas:
            local = f":{falha.linha}" if falha.linha else ""
            linhas += [f"  {falha.arquivo}{local} [{falha.motivo}] {falha.mensagem}"]
        linhas += [""]

    linhas += [regua]
    return "\n".join(linhas)


def para_dict(varredura: Varredura) -> dict[str, object]:
    """Estrutura JSON da varredura: achados mais metadados de execucao.

    Os metadados existem para rastreabilidade: sem saber quantos arquivos
    falharam, as metricas da avaliacao perdem o denominador.
    """
    resumo = resumir(varredura)
    return {
        "ferramenta": "owasp-scan",
        "versao": varredura.versao,
        "raiz": varredura.raiz,
        "momento": varredura.momento.isoformat(timespec="seconds"),
        "varredura": {
            "arquivos_analisados": varredura.arquivos_analisados,
            "arquivos_de_configuracao": varredura.arquivos_de_configuracao,
            "arquivos_com_falha": len(varredura.falhas),
            "falhas": [
                {
                    "arquivo": falha.arquivo,
                    "motivo": falha.motivo,
                    "mensagem": falha.mensagem,
                    "linha": falha.linha,
                }
                for falha in varredura.falhas
            ],
        },
        "resumo": {
            "total": resumo.total,
            "rastreados_por_taint": resumo.confirmados,
            "candidatos_heuristicos": resumo.candidatos,
            "por_severidade": resumo.por_severidade,
            "por_owasp": resumo.por_owasp,
            "por_cwe": resumo.por_cwe,
            "por_arquivo": resumo.por_arquivo,
        },
        "achados": [achado.para_dict() for achado in ordenar(varredura.achados)],
    }


__all__ = [
    "Varredura",
    "Resumo",
    "resumir",
    "ordenar",
    "formatar_texto",
    "para_dict",
]
