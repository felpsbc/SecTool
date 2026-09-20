"""Motor de taint tracking intraprocedural, insensivel a fluxo.

Regras de aproximacao, declaradas de proposito (ver README):

1. Intraprocedural: cada funcao e um escopo; taint nao atravessa a fronteira
   de chamada entre funcoes definidas no projeto.
2. Insensivel a fluxo: se um nome recebe dado contaminado em algum ponto do
   escopo, ele conta como contaminado em todo o escopo. Cobre laços e ramos
   `if/else`, ao custo de falso positivo quando so um ramo contamina.
3. Chamada desconhecida propaga: `y = f(x)` com `x` contaminado contamina `y`.
   Assume o pior caso para nao produzir falso negativo silencioso.

O motor nao decide se algo e vulneravel: ele devolve, para cada valor, as
`Procedencia`s que o alcancam — fonte, sanitizadores aplicados no caminho e
como o dado chegou ali. Quem interpreta isso e o detector, que conhece a CWE.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace

from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import (
    CATALOGO_PADRAO,
    Catalogo,
    nome_pontilhado,
    nomes_de_parametros_de_rota,
)

NOME_ESCOPO_MODULO = "<modulo>"
FONTE_PARAMETRO_DE_ROTA = "parametro de rota"

# Nos que abrem um escopo proprio e por isso interrompem a coleta do escopo pai.
# Lambda fica de fora de proposito: nao pode conter atribuicao relevante, e
# trata-la como fronteira criaria ponto cego para sinks escritos dentro dela.
_FRONTEIRAS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

# Estruturas que tornam uma atribuicao condicional (afeta a confianca).
_CONTROLE_DE_FLUXO = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.ExceptHandler,
    ast.match_case,
)


@dataclass(frozen=True)
class Procedencia:
    """Como uma fonte nao confiavel alcancou um valor."""

    fonte: str  # rotulo da fonte, ex. "request.args"
    sanitizadores: frozenset[str] = frozenset()  # rotulos aplicados no caminho
    via_chamada: bool = False  # passou por funcao nao analisada
    condicional: bool = False  # atribuida dentro de if/laço/try

    def com_sanitizador(self, rotulo: str) -> Procedencia:
        return replace(self, sanitizadores=self.sanitizadores | {rotulo})


@dataclass
class Escopo:
    """Resultado da analise de taint para um modulo, classe ou funcao."""

    nome: str
    no: ast.AST
    catalogo: Catalogo
    contaminados: dict[str, frozenset[Procedencia]] = field(default_factory=dict)
    # nome -> expressoes atribuidas a ele neste escopo, para resolucao de
    # literais (ver `literais_de_string`)
    atribuicoes: dict[str, tuple[ast.AST, ...]] = field(default_factory=dict)

    def esta_contaminado(self, nome: str) -> bool:
        """Ha dado nao confiavel neste nome? Ignora sanitizacao: quem avalia
        sanitizacao e o detector, que sabe qual CWE esta em jogo."""
        return bool(self.contaminados.get(nome))

    def procedencias_de(self, nome: str) -> frozenset[Procedencia]:
        return self.contaminados.get(nome, frozenset())

    def origens_de(self, nome: str) -> frozenset[str]:
        return frozenset(p.fonte for p in self.procedencias_de(nome))

    def procedencias_da_expressao(self, no: ast.AST) -> frozenset[Procedencia]:
        return _procedencias(no, self.contaminados, self.catalogo)

    def origens_da_expressao(self, no: ast.AST) -> frozenset[str]:
        """Fontes nao confiaveis que alcancam o valor desta expressao."""
        return frozenset(p.fonte for p in self.procedencias_da_expressao(no))

    def expressao_contaminada(self, no: ast.AST) -> bool:
        return bool(self.procedencias_da_expressao(no))

    @property
    def nomes_contaminados(self) -> frozenset[str]:
        return frozenset(nome for nome, p in self.contaminados.items() if p)


def _procedencias(
    no: ast.AST | None,
    contaminados: dict[str, frozenset[Procedencia]],
    catalogo: Catalogo,
) -> frozenset[Procedencia]:
    """Procedencias que alcancam a expressao. Vazio = nao contaminado."""
    if no is None:
        return frozenset()

    pontilhado = nome_pontilhado(no)
    if pontilhado is not None:
        fonte = catalogo.fonte_para(pontilhado)
        if fonte is not None:
            return frozenset({Procedencia(fonte=fonte.rotulo)})
        conhecidas = contaminados.get(pontilhado)
        if conhecidas:
            return conhecidas
        if isinstance(no, ast.Name):
            return frozenset()

    def uniao(*nos: ast.AST | None) -> frozenset[Procedencia]:
        resultado: frozenset[Procedencia] = frozenset()
        for filho in nos:
            if filho is not None:
                resultado |= _procedencias(filho, contaminados, catalogo)
        return resultado

    match no:
        case ast.Constant():
            return frozenset()
        case ast.Call(func=func, args=args, keywords=palavras):
            de_dentro = uniao(func, *args, *(p.value for p in palavras))
            if not de_dentro:
                return frozenset()
            sanitizador = catalogo.sanitizador_para(no)
            if sanitizador is not None:
                # O taint continua registrado, mas marcado como sanitizado:
                # cabe ao detector saber se aquela CWE foi neutralizada.
                return frozenset(
                    p.com_sanitizador(sanitizador.rotulo) for p in de_dentro
                )
            if catalogo.e_operacao_de_string(no):
                return de_dentro
            # Chamada opaca: propaga (regra 3), mas registra a incerteza.
            return frozenset(replace(p, via_chamada=True) for p in de_dentro)
        case ast.Attribute(value=valor) | ast.Starred(value=valor) | ast.Await(
            value=valor
        ):
            return uniao(valor)
        case ast.Subscript(value=valor, slice=indice):
            return uniao(valor, indice)
        case ast.BinOp(left=esquerda, right=direita):
            return uniao(esquerda, direita)
        case ast.UnaryOp(operand=operando):
            return uniao(operando)
        case ast.BoolOp(values=valores):
            return uniao(*valores)
        case ast.IfExp(body=corpo, orelse=senao, test=teste):
            return uniao(corpo, senao, teste)
        case ast.JoinedStr(values=valores):
            return uniao(*valores)
        case ast.FormattedValue(value=valor, format_spec=formato):
            return uniao(valor, formato)
        case ast.List(elts=itens) | ast.Tuple(elts=itens) | ast.Set(elts=itens):
            return uniao(*itens)
        case ast.Dict(keys=chaves, values=valores):
            return uniao(*chaves, *valores)
        case ast.Compare(left=esquerda, comparators=comparados):
            return uniao(esquerda, *comparados)
        case ast.NamedExpr(value=valor):
            return uniao(valor)
        case ast.ListComp(elt=elemento, generators=geradores) | ast.SetComp(
            elt=elemento, generators=geradores
        ) | ast.GeneratorExp(elt=elemento, generators=geradores):
            return uniao(elemento, *(g.iter for g in geradores))
        case ast.DictComp(key=chave, value=valor, generators=geradores):
            return uniao(chave, valor, *(g.iter for g in geradores))
        case _:
            return frozenset()


def _alvos(no: ast.AST) -> list[str]:
    """Nomes pontilhados atribuidos por um alvo de atribuicao."""
    match no:
        case ast.Name(id=identificador):
            return [identificador]
        case ast.Attribute():
            pontilhado = nome_pontilhado(no)
            return [pontilhado] if pontilhado else []
        case ast.Starred(value=valor):
            return _alvos(valor)
        case ast.Tuple(elts=itens) | ast.List(elts=itens):
            return [nome for item in itens for nome in _alvos(item)]
        case ast.Subscript(value=valor):
            # `d["k"] = contaminado` contamina o container inteiro.
            return _alvos(valor)
        case _:
            return []


@dataclass(frozen=True)
class _Fluxo:
    """Uma atribuicao do escopo: quais nomes recebem qual expressao."""

    nomes: tuple[str, ...]
    valor: ast.AST
    condicional: bool


def _fluxos_do_escopo(no: ast.AST) -> list[_Fluxo]:
    """Atribuicoes dentro de um escopo, sem descer em escopos aninhados."""
    fluxos: list[_Fluxo] = []

    def registrar(alvos: list[str], valor: ast.AST, condicional: bool) -> None:
        if alvos:
            fluxos.append(_Fluxo(tuple(alvos), valor, condicional))

    def visitar(atual: ast.AST, condicional: bool, raiz: bool = False) -> None:
        if not raiz and isinstance(atual, _FRONTEIRAS):
            return
        match atual:
            case ast.Assign(targets=alvos, value=valor):
                for alvo in alvos:
                    registrar(_alvos(alvo), valor, condicional)
            case ast.AnnAssign(target=alvo, value=valor) if valor is not None:
                registrar(_alvos(alvo), valor, condicional)
            case ast.AugAssign(target=alvo, value=valor):
                registrar(_alvos(alvo), valor, condicional)
            case ast.For(target=alvo, iter=iteravel) | ast.AsyncFor(
                target=alvo, iter=iteravel
            ):
                registrar(_alvos(alvo), iteravel, True)
            case ast.NamedExpr(target=alvo, value=valor):
                registrar(_alvos(alvo), valor, condicional)
            case ast.With(items=itens) | ast.AsyncWith(items=itens):
                for item in itens:
                    if item.optional_vars is not None:
                        registrar(
                            _alvos(item.optional_vars), item.context_expr, condicional
                        )
            case ast.comprehension(target=alvo, iter=iteravel):
                registrar(_alvos(alvo), iteravel, True)
        for filho in ast.iter_child_nodes(atual):
            visitar(filho, condicional or isinstance(atual, _CONTROLE_DE_FLUXO))

    visitar(no, condicional=False, raiz=True)
    return fluxos


def _nome_do_escopo(prefixo: str, no: ast.AST) -> str:
    nome = getattr(no, "name", NOME_ESCOPO_MODULO)
    if prefixo in ("", NOME_ESCOPO_MODULO):
        return nome
    return f"{prefixo}.{nome}"


def parametros_de_rota_por_escopo(arvore: ast.AST) -> dict[str, frozenset[str]]:
    """Mapeia cada view de rota aos seus parametros vindos da URL.

    Parametro de rota e fonte nao confiavel para todos os detectores, nao so
    para IDOR: `/usuario/<uid>` concatenado numa query e SQL Injection.
    """
    mapa: dict[str, frozenset[str]] = {}

    def visitar(no: ast.AST, prefixo: str) -> None:
        for filho in ast.iter_child_nodes(no):
            if isinstance(filho, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                nome = _nome_do_escopo(prefixo, filho)
                parametros = nomes_de_parametros_de_rota(filho)
                if parametros:
                    mapa[nome] = parametros
                visitar(filho, nome)
            else:
                visitar(filho, prefixo)

    visitar(arvore, "")
    return mapa


def analisar_taint(
    arquivo: ArquivoAnalisado,
    catalogo: Catalogo = CATALOGO_PADRAO,
    parametros_contaminados: dict[str, frozenset[str]] | None = None,
) -> list[Escopo]:
    """Analisa um modulo e devolve um Escopo por modulo/classe/funcao.

    `parametros_contaminados` semeia nomes ja contaminados por escopo. Quando
    omitido, os parametros de rota das views sao semeados automaticamente;
    passe `{}` para desligar essa semeadura.
    """
    escopos: list[Escopo] = []
    sementes = (
        parametros_contaminados
        if parametros_contaminados is not None
        else parametros_de_rota_por_escopo(arquivo.arvore)
    )

    def processar(
        no: ast.AST, prefixo: str, herdados: dict[str, frozenset[Procedencia]]
    ) -> None:
        nome_escopo = _nome_do_escopo(prefixo, no)
        contaminados = dict(herdados)
        for nome in sementes.get(nome_escopo, frozenset()):
            contaminados[nome] = contaminados.get(nome, frozenset()) | frozenset(
                {Procedencia(fonte=FONTE_PARAMETRO_DE_ROTA)}
            )

        fluxos = _fluxos_do_escopo(no)
        # Ponto fixo: repete ate o conjunto de contaminados parar de crescer.
        # Isso torna a analise independente da ordem textual (regra 2).
        mudou = True
        while mudou:
            mudou = False
            for fluxo in fluxos:
                procedencias = _procedencias(fluxo.valor, contaminados, catalogo)
                if not procedencias:
                    continue
                if fluxo.condicional:
                    procedencias = frozenset(
                        replace(p, condicional=True) for p in procedencias
                    )
                for nome in fluxo.nomes:
                    anterior = contaminados.get(nome, frozenset())
                    novo = anterior | procedencias
                    if novo != anterior:
                        contaminados[nome] = novo
                        mudou = True

        atribuicoes: dict[str, tuple[ast.AST, ...]] = {}
        for fluxo in fluxos:
            for nome in fluxo.nomes:
                atribuicoes[nome] = atribuicoes.get(nome, ()) + (fluxo.valor,)

        escopos.append(
            Escopo(
                nome=nome_escopo,
                no=no,
                catalogo=catalogo,
                contaminados=contaminados,
                atribuicoes=atribuicoes,
            )
        )

        for filho in ast.iter_child_nodes(no):
            _descer(filho, nome_escopo, contaminados)

    def _descer(
        no: ast.AST, prefixo: str, herdados: dict[str, frozenset[Procedencia]]
    ) -> None:
        if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            processar(no, prefixo, herdados)
            return
        for filho in ast.iter_child_nodes(no):
            _descer(filho, prefixo, herdados)

    processar(arquivo.arvore, "", {})
    return escopos


def escopo_de(escopos: list[Escopo], nome: str) -> Escopo:
    """Busca um escopo pelo nome qualificado. Levanta KeyError se nao existir."""
    for escopo in escopos:
        if escopo.nome == nome:
            return escopo
    disponiveis = ", ".join(sorted(e.nome for e in escopos))
    raise KeyError(f"escopo {nome!r} nao encontrado. Disponiveis: {disponiveis}")


def nos_do_escopo(escopo: Escopo) -> list[ast.AST]:
    """Nos que pertencem a este escopo, sem descer em escopos aninhados.

    E o que um detector deve percorrer: garante que cada sink seja atribuido
    ao escopo que de fato o contem, sem duplicar achados.
    """
    coletados: list[ast.AST] = []

    def visitar(atual: ast.AST, raiz: bool = False) -> None:
        if not raiz:
            if isinstance(atual, _FRONTEIRAS):
                return
            coletados.append(atual)
        for filho in ast.iter_child_nodes(atual):
            visitar(filho)

    visitar(escopo.no, raiz=True)
    return coletados


def literais_de_string(escopo: Escopo, no: ast.AST, profundidade: int = 3) -> str:
    """Literais de string que compoem uma expressao, resolvendo variaveis.

    `consulta = "SELECT ... WHERE id = ?"` seguido de `execute(consulta)`
    devolve o texto da consulta. Inspeciona VALORES de constantes ja
    extraidas pela AST; nao e parsing de codigo por expressao regular.
    """
    partes: list[str] = []
    visitados: set[str] = set()

    def visitar(expressao: ast.AST, nivel: int) -> None:
        if nivel < 0:
            return
        for filho in ast.walk(expressao):
            if isinstance(filho, ast.Constant) and isinstance(filho.value, str):
                partes.append(filho.value)
                continue
            nome = nome_pontilhado(filho)
            if nome and nome not in visitados:
                visitados.add(nome)
                for valor in escopo.atribuicoes.get(nome, ()):
                    visitar(valor, nivel - 1)

    visitar(no, profundidade)
    return " ".join(partes)
