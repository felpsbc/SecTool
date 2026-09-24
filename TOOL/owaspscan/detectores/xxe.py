"""Detector de XML External Entity (CWE-611 -> A05:2021 Security Misconfiguration).

XXE e, antes de tudo, configuracao do parser. Por isso o detector separa:

1. **Configuracao explicitamente insegura** — `lxml.etree.XMLParser` com
   `resolve_entities=True`, `no_network=False` ou `load_dtd=True` sem
   desligar entidades; `setFeature(feature_external_ges, True)` no SAX.
   Reportada na linha da configuracao, com confianca alta: o codigo pede
   para resolver entidades externas, qualquer que seja a entrada.
2. **Dado da requisicao chegando ao parser do lxml** sem parser seguro
   declarado. Confianca media: o padrao do lxml mudou na versao 5.0 e o
   motor nao ve a versao instalada.

`xml.etree`, `minidom` e `xml.sax` da stdlib NAO sao reportados: desde o
Python 3.7.1 eles nao resolvem entidades externas por padrao. O risco que
resta neles e expansao recursiva (CWE-776, "billion laughs"), fora do
escopo deste detector. `defusedxml` e o caminho seguro recomendado.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo, nome_pontilhado
from owaspscan.motor.confianca import justificativa, procedencias_relevantes
from owaspscan.motor.estrutura import (
    argumento,
    mapa_de_importacoes,
    nome_qualificado,
    valor_constante,
)
from owaspscan.motor.taint import Escopo, nos_do_escopo

RECOMENDACAO = (
    "Use defusedxml (defusedxml.ElementTree.fromstring / defusedxml.lxml) "
    "para XML de origem externa. Com lxml, declare o parser explicitamente: "
    "etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)."
)

# Funcoes do lxml que parseiam XML e aceitam `parser` (posicional 1 ou kw).
PARSERS_LXML: frozenset[str] = frozenset(
    {
        "lxml.etree.fromstring",
        "lxml.etree.fromstringlist",
        "lxml.etree.XML",
        "lxml.etree.parse",
        "lxml.etree.iterparse",
        "lxml.objectify.fromstring",
        "lxml.objectify.parse",
        "lxml.objectify.XML",
    }
)

FABRICAS_DE_PARSER_LXML: frozenset[str] = frozenset(
    {"lxml.etree.XMLParser", "lxml.objectify.makeparser"}
)

# Features SAX que liberam entidades externas quando ligadas.
FEATURES_SAX_EXTERNAS: frozenset[str] = frozenset(
    {
        "feature_external_ges",
        "feature_external_pes",
        "http://xml.org/sax/features/external-general-entities",
        "http://xml.org/sax/features/external-parameter-entities",
    }
)


def motivo_de_parser_inseguro(chamada: ast.Call) -> str | None:
    """Por que esta construcao de XMLParser resolve entidades externas?"""
    resolve = valor_constante(argumento(chamada, None, "resolve_entities"))
    rede = valor_constante(argumento(chamada, None, "no_network"))
    dtd = valor_constante(argumento(chamada, None, "load_dtd"))
    if resolve is True:
        return "resolve_entities=True"
    if rede is False:
        return "no_network=False (permite buscar entidades pela rede)"
    if dtd is True and resolve is not False:
        return "load_dtd=True sem resolve_entities=False"
    return None


def _e_parser_seguro(chamada: ast.Call) -> bool:
    """O parser desliga explicitamente a resolucao de entidades?"""
    resolve = valor_constante(argumento(chamada, None, "resolve_entities"))
    return resolve is False or resolve == "internal"


@dataclass(frozen=True)
class DetectorXxe:
    """Detector de CWE-611 para lxml e SAX."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "XML External Entity"
    cwe: str = "CWE-611"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        importacoes = mapa_de_importacoes(arquivo.arvore)
        modulo = escopos[0] if escopos else None
        achados: list[Achado] = []
        for escopo in escopos:
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                qualificado = nome_qualificado(no.func, importacoes) or ""
                achado = (
                    self._da_fabrica(arquivo, no, qualificado)
                    or self._do_sax(arquivo, no)
                    or self._do_parse(arquivo, escopo, modulo, no, qualificado, importacoes)
                )
                if achado is not None:
                    achados.append(achado)
        return achados

    def _da_fabrica(
        self, arquivo: ArquivoAnalisado, no: ast.Call, qualificado: str
    ) -> Achado | None:
        if qualificado not in FABRICAS_DE_PARSER_LXML:
            return None
        motivo = motivo_de_parser_inseguro(no)
        if motivo is None:
            return None
        return self._montar(
            arquivo,
            no,
            confianca="alta",
            descricao=(
                f"Parser XML configurado com {motivo}: entidades externas sao "
                "resolvidas, permitindo ler arquivos locais (file:///etc/passwd) "
                "ou fazer requisicoes a partir do servidor (SSRF)."
            ),
        )

    def _do_sax(self, arquivo: ArquivoAnalisado, no: ast.Call) -> Achado | None:
        if not (isinstance(no.func, ast.Attribute) and no.func.attr == "setFeature"):
            return None
        if len(no.args) < 2 or valor_constante(no.args[1]) is not True:
            return None
        feature = no.args[0]
        nome = valor_constante(feature)
        if not isinstance(nome, str):
            pontilhado = nome_pontilhado(feature)
            nome = pontilhado.split(".")[-1] if pontilhado else ""
        if nome not in FEATURES_SAX_EXTERNAS:
            return None
        return self._montar(
            arquivo,
            no,
            confianca="alta",
            descricao=(
                "Parser SAX com resolucao de entidades externas ligada "
                f"({nome}), desfazendo o padrao seguro da stdlib."
            ),
        )

    def _do_parse(
        self,
        arquivo: ArquivoAnalisado,
        escopo: Escopo,
        modulo: Escopo | None,
        no: ast.Call,
        qualificado: str,
        importacoes: dict[str, str],
    ) -> Achado | None:
        if qualificado not in PARSERS_LXML or not no.args:
            return None
        procedencias = procedencias_relevantes(
            escopo.procedencias_da_expressao(no.args[0]), self.cwe, self.catalogo
        )
        if not procedencias:
            return None

        parser = argumento(no, 1, "parser")
        construcao = self._resolver_parser(parser, escopo, modulo, importacoes)
        if construcao is not None:
            if _e_parser_seguro(construcao):
                return None
            if motivo_de_parser_inseguro(construcao) is not None:
                # Ja reportado na linha do XMLParser: uma causa, um achado.
                return None
        elif parser is not None:
            # Parser vindo de lugar que o motor nao resolve: nao acusar.
            return None

        fontes = ", ".join(sorted({p.fonte for p in procedencias}))
        return self._montar(
            arquivo,
            no,
            confianca="media",
            descricao=(
                f"XML vindo de {fontes} e parseado por {qualificado} sem parser "
                "que desligue entidades externas. Em lxml anterior a 5.0 o "
                "padrao resolve entidades externas locais; a versao instalada "
                "nao e visivel na analise estatica."
                + justificativa(procedencias)
            ),
        )

    def _resolver_parser(
        self,
        parser: ast.AST | None,
        escopo: Escopo,
        modulo: Escopo | None,
        importacoes: dict[str, str],
    ) -> ast.Call | None:
        """Encontra a chamada que construiu o parser, se estiver a vista."""
        if parser is None:
            return None
        candidatos: list[ast.AST] = [parser]
        nome = nome_pontilhado(parser)
        if nome:
            for origem in (escopo, modulo):
                if origem is not None:
                    candidatos.extend(origem.atribuicoes.get(nome, ()))
        for candidato in candidatos:
            if isinstance(candidato, ast.Call) and (
                nome_qualificado(candidato.func, importacoes) in FABRICAS_DE_PARSER_LXML
            ):
                return candidato
        return None

    def _montar(
        self, arquivo: ArquivoAnalisado, no: ast.AST, confianca: str, descricao: str
    ) -> Achado:
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=self.cwe,
            severidade="alta",
            confianca=confianca,
            trecho=arquivo.trecho_de(no),
            descricao=descricao,
            recomendacao=RECOMENDACAO,
        )
