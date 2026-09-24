"""Contrato interno de achado.

Todo detector devolve objetos `Achado`. O mapeamento CWE -> OWASP e o nome
da vulnerabilidade sao derivados de `MAPA_CWE_OWASP` na construcao, para que
nenhum detector possa inventar classificacao.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Literal

Severidade = Literal["alta", "media", "baixa"]
Confianca = Literal["alta", "media", "baixa"]

SEVERIDADES_VALIDAS: frozenset[str] = frozenset({"alta", "media", "baixa"})
CONFIANCAS_VALIDAS: frozenset[str] = frozenset({"alta", "media", "baixa"})


@dataclass(frozen=True)
class ClasseVulnerabilidade:
    """Classificacao canonica de uma CWE suportada."""

    cwe: str
    owasp: str
    vulnerabilidade: str


# Mapeamento fixo definido no CLAUDE.md. Nao estender sem atualizar o teste
# de contrato: e ele que impede classificacao inventada. Cada categoria foi
# conferida contra a lista oficial "List of Mapped CWEs" do OWASP Top 10:2021.
MAPA_CWE_OWASP: dict[str, ClasseVulnerabilidade] = {
    "CWE-89": ClasseVulnerabilidade(
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        vulnerabilidade="SQL Injection",
    ),
    "CWE-79": ClasseVulnerabilidade(
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        vulnerabilidade="Cross-Site Scripting",
    ),
    "CWE-639": ClasseVulnerabilidade(
        cwe="CWE-639",
        owasp="A01:2021 Broken Access Control",
        vulnerabilidade="IDOR",
    ),
    "CWE-22": ClasseVulnerabilidade(
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        vulnerabilidade="Path Traversal",
    ),
    "CWE-601": ClasseVulnerabilidade(
        cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        vulnerabilidade="Open Redirect",
    ),
    "CWE-352": ClasseVulnerabilidade(
        cwe="CWE-352",
        owasp="A01:2021 Broken Access Control",
        vulnerabilidade="Cross-Site Request Forgery",
    ),
    "CWE-862": ClasseVulnerabilidade(
        cwe="CWE-862",
        owasp="A01:2021 Broken Access Control",
        vulnerabilidade="Missing Authorization",
    ),
    "CWE-916": ClasseVulnerabilidade(
        cwe="CWE-916",
        owasp="A02:2021 Cryptographic Failures",
        vulnerabilidade="Weak Password Hash",
    ),
    "CWE-256": ClasseVulnerabilidade(
        cwe="CWE-256",
        owasp="A04:2021 Insecure Design",
        vulnerabilidade="Unprotected Storage of Credentials",
    ),
    "CWE-611": ClasseVulnerabilidade(
        cwe="CWE-611",
        owasp="A05:2021 Security Misconfiguration",
        vulnerabilidade="XML External Entity (XXE)",
    ),
    "CWE-614": ClasseVulnerabilidade(
        cwe="CWE-614",
        owasp="A05:2021 Security Misconfiguration",
        vulnerabilidade="Cookie Without Secure Flag",
    ),
    "CWE-1004": ClasseVulnerabilidade(
        cwe="CWE-1004",
        owasp="A05:2021 Security Misconfiguration",
        vulnerabilidade="Cookie Without HttpOnly Flag",
    ),
    "CWE-287": ClasseVulnerabilidade(
        cwe="CWE-287",
        owasp="A07:2021 Identification and Authentication Failures",
        vulnerabilidade="Improper Authentication",
    ),
    "CWE-307": ClasseVulnerabilidade(
        cwe="CWE-307",
        owasp="A07:2021 Identification and Authentication Failures",
        vulnerabilidade="Excessive Authentication Attempts",
    ),
    "CWE-613": ClasseVulnerabilidade(
        cwe="CWE-613",
        owasp="A07:2021 Identification and Authentication Failures",
        vulnerabilidade="Insufficient Session Expiration",
    ),
    "CWE-798": ClasseVulnerabilidade(
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        vulnerabilidade="Hard-coded Credentials",
    ),
}

# Ordem do contrato interno, usada em serializacao e no teste de contrato.
CAMPOS_CONTRATO: tuple[str, ...] = (
    "arquivo",
    "linha",
    "cwe",
    "owasp",
    "vulnerabilidade",
    "severidade",
    "confianca",
    "trecho",
    "descricao",
    "recomendacao",
)


class ClassificacaoInvalida(ValueError):
    """CWE desconhecida ou classificacao incoerente com MAPA_CWE_OWASP."""


@dataclass(frozen=True)
class Achado:
    """Um achado de vulnerabilidade, no formato fixo do contrato interno."""

    arquivo: str
    linha: int
    cwe: str
    owasp: str
    vulnerabilidade: str
    severidade: Severidade
    confianca: Confianca
    trecho: str
    descricao: str
    recomendacao: str

    def __post_init__(self) -> None:
        classe = MAPA_CWE_OWASP.get(self.cwe)
        if classe is None:
            conhecidas = ", ".join(sorted(MAPA_CWE_OWASP))
            raise ClassificacaoInvalida(
                f"CWE desconhecida: {self.cwe!r}. Conhecidas: {conhecidas}"
            )
        if self.owasp != classe.owasp:
            raise ClassificacaoInvalida(
                f"{self.cwe} mapeia para {classe.owasp!r}, recebido {self.owasp!r}"
            )
        if self.vulnerabilidade != classe.vulnerabilidade:
            raise ClassificacaoInvalida(
                f"{self.cwe} e {classe.vulnerabilidade!r}, "
                f"recebido {self.vulnerabilidade!r}"
            )
        if self.severidade not in SEVERIDADES_VALIDAS:
            raise ClassificacaoInvalida(
                f"severidade invalida: {self.severidade!r}"
            )
        if self.confianca not in CONFIANCAS_VALIDAS:
            raise ClassificacaoInvalida(f"confianca invalida: {self.confianca!r}")
        if self.linha < 1:
            raise ClassificacaoInvalida(f"linha deve ser >= 1, recebido {self.linha}")

    def para_dict(self) -> dict[str, object]:
        """Serializa na ordem do contrato, pronto para JSON."""
        bruto = asdict(self)
        return {campo: bruto[campo] for campo in CAMPOS_CONTRATO}


def criar_achado(
    *,
    arquivo: str,
    linha: int,
    cwe: str,
    severidade: Severidade,
    confianca: Confianca,
    trecho: str,
    descricao: str,
    recomendacao: str,
) -> Achado:
    """Cria um Achado derivando owasp e vulnerabilidade do mapa canonico.

    Esta e a via que os detectores devem usar: eles informam a CWE e a
    classificacao OWASP vem do mapa, nunca do detector.
    """
    classe = MAPA_CWE_OWASP.get(cwe)
    if classe is None:
        conhecidas = ", ".join(sorted(MAPA_CWE_OWASP))
        raise ClassificacaoInvalida(
            f"CWE desconhecida: {cwe!r}. Conhecidas: {conhecidas}"
        )
    return Achado(
        arquivo=arquivo,
        linha=linha,
        cwe=classe.cwe,
        owasp=classe.owasp,
        vulnerabilidade=classe.vulnerabilidade,
        severidade=severidade,
        confianca=confianca,
        trecho=trecho,
        descricao=descricao,
        recomendacao=recomendacao,
    )


def campos_do_achado() -> tuple[str, ...]:
    """Nomes dos campos da dataclass, na ordem declarada."""
    return tuple(campo.name for campo in fields(Achado))
