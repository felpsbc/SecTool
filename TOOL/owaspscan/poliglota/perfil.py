"""Perfil de linguagem: o que o motor generico precisa saber de cada gramatica.

O motor de taint (`motor.py`) e o detector (`detector.py`) nao conhecem
nenhuma linguagem. Tudo que e especifico — tipos de no da gramatica do
tree-sitter, fontes, sinks, sanitizadores — mora num `Perfil`.

Nomes pontilhados: cada perfil traduz expressoes de acesso para uma forma
canonica com "." como separador (`req.query.id`, `request.getParameter()`,
`$_GET`), e os padroes de fonte/sink/sanitizador sao escritos nessa forma.
Um padrao que comeca com "*." casa por sufixo: "*.query" casa `db.query` e
`this.pool.query`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # tree-sitter e opcional: so o tipo e importado aqui
    from tree_sitter import Node

CWES_DE_INJECAO = frozenset({"CWE-89", "CWE-79", "CWE-22", "CWE-601"})
# Rotulo de sanitizacao para conversao numerica feita pela sintaxe da
# linguagem (cast `(int)$x` do PHP): numero nao carrega payload de injecao.
CONVERSAO_NUMERICA = "conversao numerica"


def casa(padrao: str, nome: str) -> bool:
    """O nome pontilhado casa o padrao? "*.x" casa por sufixo."""
    if padrao.startswith("*."):
        resto = padrao[2:]
        return nome == resto or nome.endswith("." + resto)
    return nome == padrao


def casa_algum(padroes, nome: str | None) -> str | None:
    """Primeiro padrao que casa o nome, ou None."""
    if nome is None:
        return None
    for padrao in padroes:
        if casa(padrao, nome):
            return padrao
    return None


@dataclass(frozen=True)
class Chamada:
    """Uma chamada de funcao/metodo (ou `new Classe(...)`) ja decomposta."""

    nome: str  # nome pontilhado do alvo, ex. "db.query", "new File"
    argumentos: tuple[Node, ...]
    receptor: Node | None = None  # objeto do metodo, quando houver


@dataclass(frozen=True)
class Atribuicao:
    """`alvo = valor`, inclusive declaracao com inicializador e desestruturacao."""

    alvos: tuple[str, ...]  # nomes pontilhados que recebem o valor
    valor: Node
    alvo: Node | None = None  # no do lado esquerdo, para sinks de atribuicao


@dataclass(frozen=True)
class Sink:
    """Ponto onde dado nao confiavel vira vulnerabilidade."""

    cwe: str
    padroes: tuple[str, ...]
    descricao: str  # ex. "a string SQL de db.query"
    argumentos: tuple[int, ...] | None = (0,)  # None = qualquer argumento
    atribuicao: bool = False  # sink e o alvo de uma atribuicao (el.innerHTML = x)


@dataclass(frozen=True)
class Perfil:
    linguagem: str
    fronteiras: frozenset[str]  # tipos de no que abrem escopo (funcoes)
    controle: frozenset[str]  # tipos de no que tornam a atribuicao condicional
    fontes: tuple[str, ...]  # acessos que SAO dado nao confiavel (prefixo)
    fontes_de_chamada: tuple[str, ...]  # chamadas que DEVOLVEM dado nao confiavel
    sanitizadores: dict[str, frozenset[str]]  # padrao -> CWEs neutralizadas
    repassadores: tuple[str, ...]  # chamadas que repassam o dado sem esconder o caminho
    mutadores: tuple[str, ...]  # `sb.append(x)` contamina `sb`
    sinks: tuple[Sink, ...]
    recomendacoes: dict[str, str]  # CWE -> recomendacao na linguagem
    nome: Callable[[Node], str | None]
    chamada: Callable[[Node], Chamada | None]
    atribuicao: Callable[[Node], Atribuicao | None]
    texto_literal: Callable[[Node], str | None]  # literal de string puro, sem interpolacao
    # Extensoes opcionais da gramatica:
    parametros_contaminados: Callable[[Node], dict[str, str]] = field(
        default=lambda no: {}
    )
    saidas_html: Callable[[Node], tuple[Node, ...]] = field(
        default=lambda no: ()
    )  # echo do PHP, dangerouslySetInnerHTML do React...
    conversao_numerica: Callable[[Node], Node | None] = field(
        default=lambda no: None
    )  # cast (int) do PHP: devolve a expressao convertida
    pares_de_credencial: Callable[[Node], tuple[str, Node] | None] = field(
        default=lambda no: None
    )  # chave literal => valor ({password: "x"}, 'senha' => 'x')
    condicoes: frozenset[str] = frozenset()  # tipos de no de `if` (guardas)

    def sanitizador(self, nome: str | None) -> tuple[str, frozenset[str]] | None:
        padrao = casa_algum(self.sanitizadores, nome)
        if padrao is None:
            return None
        return padrao, self.sanitizadores[padrao]

    def neutraliza(self, sanitizadores: frozenset[str], cwe: str) -> bool:
        return any(
            cwe in self.sanitizadores.get(rotulo, frozenset())
            or (rotulo == CONVERSAO_NUMERICA and cwe in CWES_DE_INJECAO)
            for rotulo in sanitizadores
        )
