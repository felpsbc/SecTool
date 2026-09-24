"""Consultas estruturais sobre a AST, compartilhadas pelos detectores.

O motor de taint responde "de onde veio este valor". Varios detectores da
A01/A05/A07 precisam de outra pergunta: "como este codigo esta montado" —
qual biblioteca foi importada, que chave de configuracao recebeu que valor,
quais metodos HTTP uma rota aceita. Tudo aqui e leitura de AST, sem regex.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterator

from owaspscan.motor.catalogo import e_view_de_rota, nome_pontilhado

# --- Importacoes ------------------------------------------------------------


def mapa_de_importacoes(arvore: ast.AST) -> dict[str, str]:
    """Alias local -> nome qualificado do modulo ou objeto importado.

    `from lxml import etree` gera {"etree": "lxml.etree"};
    `import xml.etree.ElementTree as ET` gera {"ET": "xml.etree.ElementTree"}.
    Importacoes dentro de funcoes tambem contam: o alias vale para o arquivo
    inteiro, uma aproximacao aceitavel para distinguir bibliotecas.
    """
    mapa: dict[str, str] = {}
    for no in ast.walk(arvore):
        if isinstance(no, ast.Import):
            for alias in no.names:
                if alias.asname:
                    mapa[alias.asname] = alias.name
                else:
                    # `import a.b` liga apenas o nome `a`.
                    raiz = alias.name.split(".")[0]
                    mapa.setdefault(raiz, raiz)
        elif isinstance(no, ast.ImportFrom) and no.module and not no.level:
            for alias in no.names:
                if alias.name == "*":
                    continue
                mapa[alias.asname or alias.name] = f"{no.module}.{alias.name}"
    return mapa


def nome_qualificado(no: ast.AST, importacoes: dict[str, str]) -> str | None:
    """Nome pontilhado com o primeiro segmento resolvido pelas importacoes.

    `etree.fromstring` vira `lxml.etree.fromstring` quando `etree` veio de
    `from lxml import etree`. Nomes nao importados ficam como estao.
    """
    pontilhado = nome_pontilhado(no)
    if pontilhado is None:
        return None
    primeiro, _, resto = pontilhado.partition(".")
    base = importacoes.get(primeiro, primeiro)
    return f"{base}.{resto}" if resto else base


def valor_constante(no: ast.AST | None) -> object:
    """Valor de um literal simples, ou a sentinela `NAO_CONSTANTE`."""
    if isinstance(no, ast.Constant):
        return no.value
    return NAO_CONSTANTE


class _NaoConstante:
    def __repr__(self) -> str:
        return "NAO_CONSTANTE"


NAO_CONSTANTE = _NaoConstante()


def argumento(no: ast.Call, posicao: int | None, palavra: str | None) -> ast.AST | None:
    """Argumento por posicao ou por palavra-chave, o que aparecer."""
    if palavra is not None:
        for kw in no.keywords:
            if kw.arg == palavra:
                return kw.value
    if posicao is not None and posicao < len(no.args):
        return no.args[posicao]
    return None


# --- Configuracao -----------------------------------------------------------


@dataclass(frozen=True)
class AtribuicaoDeConfiguracao:
    """Uma chave de configuracao recebendo um valor, onde quer que ocorra."""

    chave: str  # "SESSION_COOKIE_SECURE"
    valor: ast.AST
    no: ast.AST  # no usado para linha e trecho


def _e_nome_de_configuracao(nome: str) -> bool:
    """Convencao de Flask e Django: chaves de configuracao em CAIXA_ALTA."""
    return nome.isupper() and nome.replace("_", "").isalnum()


def atribuicoes_de_configuracao(arvore: ast.AST) -> Iterator[AtribuicaoDeConfiguracao]:
    """Todas as formas de definir configuracao reconhecidas.

    - `SESSION_COOKIE_SECURE = False` (settings.py do Django, classe Config)
    - `app.config["SESSION_COOKIE_SECURE"] = False`
    - `app.config.update(SESSION_COOKIE_SECURE=False)` ou com dicionario
    - `app.config.from_mapping(...)`, mesmas formas do update
    """
    for no in ast.walk(arvore):
        if isinstance(no, (ast.Assign, ast.AnnAssign)):
            alvos = no.targets if isinstance(no, ast.Assign) else [no.target]
            if no.value is None:
                continue
            for alvo in alvos:
                if isinstance(alvo, ast.Name) and _e_nome_de_configuracao(alvo.id):
                    yield AtribuicaoDeConfiguracao(alvo.id, no.value, no)
                elif (
                    isinstance(alvo, ast.Subscript)
                    and _e_config(alvo.value)
                    and isinstance(valor_constante(alvo.slice), str)
                ):
                    yield AtribuicaoDeConfiguracao(alvo.slice.value, no.value, no)
        elif isinstance(no, ast.Call) and isinstance(no.func, ast.Attribute):
            if no.func.attr not in {"update", "from_mapping"} or not _e_config(
                no.func.value
            ):
                continue
            for kw in no.keywords:
                if kw.arg:
                    yield AtribuicaoDeConfiguracao(kw.arg, kw.value, no)
            for posicional in no.args:
                if isinstance(posicional, ast.Dict):
                    for chave, valor in zip(posicional.keys, posicional.values):
                        texto = valor_constante(chave)
                        if isinstance(texto, str):
                            yield AtribuicaoDeConfiguracao(texto, valor, no)


def _e_config(no: ast.AST) -> bool:
    pontilhado = nome_pontilhado(no)
    return bool(pontilhado) and pontilhado.split(".")[-1] == "config"


# --- Rotas ------------------------------------------------------------------

METODOS_QUE_ALTERAM_ESTADO: frozenset[str] = frozenset(
    {"POST", "PUT", "PATCH", "DELETE"}
)
_DECORADOR_POR_METODO = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
}


def nomes_de_decoradores(no: ast.AST) -> list[str]:
    """Nomes pontilhados dos decoradores, sem os argumentos."""
    nomes: list[str] = []
    for decorador in getattr(no, "decorator_list", []):
        alvo = decorador.func if isinstance(decorador, ast.Call) else decorador
        pontilhado = nome_pontilhado(alvo)
        if pontilhado:
            nomes.append(pontilhado)
    return nomes


def metodos_http(no: ast.AST) -> frozenset[str]:
    """Metodos HTTP aceitos por uma view de rota. Vazio se nao for rota.

    `@app.route(..., methods=["POST"])` le a lista literal; `@app.post`
    deriva do nome; `@app.route` sem `methods` e GET, como no Flask.
    """
    if not e_view_de_rota(no):
        return frozenset()
    metodos: set[str] = set()
    for decorador in getattr(no, "decorator_list", []):
        alvo = decorador.func if isinstance(decorador, ast.Call) else decorador
        pontilhado = nome_pontilhado(alvo)
        if not pontilhado:
            continue
        ultimo = pontilhado.split(".")[-1]
        if ultimo in _DECORADOR_POR_METODO:
            metodos.add(_DECORADOR_POR_METODO[ultimo])
        elif ultimo == "route":
            declarados = (
                argumento(decorador, None, "methods")
                if isinstance(decorador, ast.Call)
                else None
            )
            if isinstance(declarados, (ast.List, ast.Tuple, ast.Set)):
                for item in declarados.elts:
                    texto = valor_constante(item)
                    if isinstance(texto, str):
                        metodos.add(texto.upper())
            elif declarados is None:
                metodos.add("GET")
            else:
                # `methods=METODOS`: nao resolvido; assume o pior caso.
                metodos.update(METODOS_QUE_ALTERAM_ESTADO)
    return frozenset(metodos)


def caminhos_da_rota(no: ast.AST) -> list[str]:
    """Regras de URL literais declaradas nos decoradores de rota."""
    caminhos: list[str] = []
    for decorador in getattr(no, "decorator_list", []):
        if not isinstance(decorador, ast.Call) or not decorador.args:
            continue
        pontilhado = nome_pontilhado(decorador.func)
        if not pontilhado:
            continue
        if pontilhado.split(".")[-1] in {"route", *_DECORADOR_POR_METODO}:
            texto = valor_constante(decorador.args[0])
            if isinstance(texto, str):
                caminhos.append(texto)
    return caminhos


def funcoes_de_rota(arvore: ast.AST) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Todas as funcoes do modulo expostas como rota HTTP."""
    for no in ast.walk(arvore):
        if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)) and e_view_de_rota(no):
            yield no


def tokens_de_nome(nome: str) -> list[str]:
    """Quebra identificador em palavras: `dbPassword` e `DB_PASSWORD` -> [db, password]."""
    palavras: list[str] = []
    atual = ""
    for anterior, caractere in zip(" " + nome, nome):
        if caractere in "_-. ":
            if atual:
                palavras.append(atual)
            atual = ""
            continue
        if caractere.isupper() and anterior.islower():
            palavras.append(atual)
            atual = ""
        atual += caractere
    if atual:
        palavras.append(atual)
    return [p.lower() for p in palavras if p]
