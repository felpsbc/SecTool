"""Perfil JavaScript/TypeScript: Node/Express no servidor e DOM no navegador.

TypeScript e TSX usam as mesmas regras: a gramatica do tree-sitter para TS
estende a de JS com os mesmos tipos de no para expressoes.
"""

from __future__ import annotations

from owaspscan.poliglota.perfil import Atribuicao, Chamada, Perfil, Sink

_OBJETOS_DE_REQUISICAO = ("req", "request", "ctx.request")

FONTES: tuple[str, ...] = (
    *(
        f"{objeto}.{campo}"
        for objeto in _OBJETOS_DE_REQUISICAO
        for campo in ("query", "body", "params", "cookies", "headers", "url", "originalUrl", "path")
    ),
    # Koa: ctx.query/params vem da requisicao; ctx.body e a RESPOSTA, fica de fora
    *(f"ctx.{campo}" for campo in ("query", "params", "headers", "url", "path")),
    # DOM: tudo que vem da URL, do referer ou do nome da janela
    *(
        f"{base}{campo}"
        for base in ("location.", "window.location.", "document.location.")
        for campo in ("search", "hash", "href", "pathname")
    ),
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "document.cookie",
    "window.name",
)

FONTES_DE_CHAMADA: tuple[str, ...] = tuple(
    f"{objeto}.{metodo}"
    for objeto in ("req", "request")
    for metodo in ("get", "header", "param")
)

_HTML = frozenset({"CWE-79"})
_SQL = frozenset({"CWE-89"})
_CAMINHO = frozenset({"CWE-22"})
_NUMERO = frozenset({"CWE-89", "CWE-79", "CWE-22", "CWE-601"})

SANITIZADORES: dict[str, frozenset[str]] = {
    # conversao numerica: numero nao carrega payload
    "parseInt": _NUMERO,
    "parseFloat": _NUMERO,
    "Number": _NUMERO,
    "Number.parseInt": _NUMERO,
    "Number.parseFloat": _NUMERO,
    # HTML
    "escape": _HTML,
    "escapeHtml": _HTML,
    "*.escapeHtml": _HTML,
    "_.escape": _HTML,
    "lodash.escape": _HTML,
    "he.encode": _HTML,
    "he.escape": _HTML,
    "validator.escape": _HTML,
    "DOMPurify.sanitize": _HTML,
    "sanitizeHtml": _HTML,
    "xss": _HTML,
    "filterXSS": _HTML,
    # encodeURIComponent codifica <, >, aspas e "/": neutraliza HTML e caminho
    "encodeURIComponent": frozenset({"CWE-79", "CWE-22"}),
    # SQL (escape do proprio driver)
    "mysql.escape": _SQL,
    "connection.escape": _SQL,
    "pool.escape": _SQL,
    "db.escape": _SQL,
    "SqlString.escape": _SQL,
    "*.escapeId": _SQL,
    # caminho: so o ultimo componente sobrevive
    "path.basename": _CAMINHO,
}

REPASSADORES: tuple[str, ...] = (
    "String",
    "path.join",
    "path.resolve",
    "*.toString",
    "*.trim",
    "*.toLowerCase",
    "*.toUpperCase",
    "*.concat",
    "*.join",
)

MUTADORES: tuple[str, ...] = ("*.push",)

_RESPOSTAS = ("res", "response", "ctx")  # ctx: Koa

SINKS: tuple[Sink, ...] = (
    Sink(
        cwe="CWE-89",
        padroes=(
            "*.query",
            "*.execute",
            "*.raw",
            "*.whereRaw",
            "*.$queryRawUnsafe",
            "*.$executeRawUnsafe",
            "sequelize.literal",
        ),
        descricao="a string SQL de {nome}",
    ),
    Sink(
        cwe="CWE-79",
        padroes=tuple(f"{r}.{m}" for r in _RESPOSTAS for m in ("send", "write", "end")),
        descricao="a resposta HTTP via {nome}",
    ),
    Sink(
        cwe="CWE-79",
        padroes=("ctx.body",),
        descricao="a resposta HTTP via atribuicao a {nome} (Koa)",
        atribuicao=True,
    ),
    Sink(
        cwe="CWE-79",
        padroes=("document.write", "document.writeln"),
        descricao="o documento via {nome}",
        argumentos=None,
    ),
    Sink(
        cwe="CWE-79",
        padroes=("*.insertAdjacentHTML",),
        descricao="o DOM via {nome}",
        argumentos=(1,),
    ),
    Sink(
        cwe="CWE-79",
        padroes=("*.innerHTML", "*.outerHTML"),
        descricao="o DOM via atribuicao a {nome}",
        atribuicao=True,
    ),
    Sink(
        cwe="CWE-79",
        padroes=("$.html", "*.html"),
        descricao="o DOM via {nome} (jQuery)",
    ),
    Sink(
        cwe="CWE-22",
        padroes=(
            *(
                f"{modulo}.{funcao}"
                for modulo in ("fs", "fs.promises", "fsPromises")
                for funcao in (
                    "readFile",
                    "readFileSync",
                    "writeFile",
                    "writeFileSync",
                    "appendFile",
                    "appendFileSync",
                    "createReadStream",
                    "createWriteStream",
                    "unlink",
                    "unlinkSync",
                    "readdir",
                    "readdirSync",
                )
            ),
            *(f"{r}.{m}" for r in _RESPOSTAS for m in ("sendFile", "download")),
        ),
        descricao="o caminho de arquivo de {nome}",
    ),
    Sink(
        cwe="CWE-601",
        padroes=(
            *(f"{r}.redirect" for r in _RESPOSTAS),
            "location.assign",
            "location.replace",
            "window.location.assign",
            "window.location.replace",
            "window.open",
        ),
        descricao="o destino de {nome}",
        argumentos=None,
    ),
    Sink(
        cwe="CWE-601",
        padroes=(
            "location",
            "location.href",
            "window.location",
            "window.location.href",
            "document.location",
            "document.location.href",
        ),
        descricao="o destino de navegacao via atribuicao a {nome}",
        atribuicao=True,
    ),
)

RECOMENDACOES: dict[str, str] = {
    "CWE-89": (
        "Use query parametrizada: db.query('... WHERE id = ?', [valor]) (mysql), "
        "'... WHERE id = $1' (pg) ou o query builder/ORM sem raw. Nunca monte SQL "
        "com concatenacao ou template string sobre dado da requisicao."
    ),
    "CWE-79": (
        "No servidor, renderize com template que escapa por padrao (EJS <%= %>, "
        "Pug, Handlebars {{ }}) ou res.json. No navegador, use textContent em vez "
        "de innerHTML; se precisar de HTML, sanitize com DOMPurify.sanitize."
    ),
    "CWE-22": (
        "Nunca use dado da requisicao como caminho. Use path.basename para nomes "
        "de arquivo, ou resolva e confine: const destino = path.resolve(BASE, nome); "
        "if (!destino.startsWith(BASE + path.sep)) recuse. Para servir arquivos, "
        "res.sendFile(nome, { root: BASE })."
    ),
    "CWE-601": (
        "Redirecione apenas para caminhos internos ou hosts de uma lista "
        "permitida: new URL(destino, base).origin === base, e recuse esquemas "
        "javascript:. Prefira mapear um identificador para a rota no servidor."
    ),
    "CWE-798": (
        "Tire o segredo do codigo: leia de process.env (falhando se ausente) ou "
        "de um cofre. Segredo em codigo de front-end e publico por definicao: "
        "mova a chamada autenticada para o servidor. Um segredo ja commitado "
        "deve ser considerado vazado: revogue e gere outro."
    ),
}

FRONTEIRAS = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    }
)

CONTROLE = frozenset(
    {
        "if_statement",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "try_statement",
        "catch_clause",
        "switch_statement",
        "ternary_expression",
    }
)

def _texto(no) -> str:
    return no.text.decode("utf-8", "replace")


def nome(no) -> str | None:
    tipo = no.type
    if tipo in ("identifier", "this"):
        return _texto(no)
    if tipo == "member_expression":
        objeto = no.child_by_field_name("object")
        propriedade = no.child_by_field_name("property")
        base = nome(objeto) if objeto is not None else None
        if base is None or propriedade is None:
            return None
        return f"{base}.{_texto(propriedade)}"
    if tipo == "subscript_expression":
        objeto = no.child_by_field_name("object")
        return nome(objeto) if objeto is not None else None
    if tipo == "call_expression":
        funcao = no.child_by_field_name("function")
        base = nome(funcao) if funcao is not None else None
        return f"{base}()" if base is not None else None
    if tipo in ("non_null_expression", "parenthesized_expression", "as_expression"):
        return nome(no.named_children[0]) if no.named_children else None
    return None


def chamada(no) -> Chamada | None:
    if no.type == "call_expression":
        funcao = no.child_by_field_name("function")
        argumentos = no.child_by_field_name("arguments")
        alvo = nome(funcao) if funcao is not None else None
        if alvo is None:
            return None
        receptor = (
            funcao.child_by_field_name("object")
            if funcao.type == "member_expression"
            else None
        )
        args = tuple(argumentos.named_children) if argumentos is not None else ()
        return Chamada(nome=alvo, argumentos=args, receptor=receptor)
    if no.type == "new_expression":
        construtor = no.child_by_field_name("constructor")
        argumentos = no.child_by_field_name("arguments")
        alvo = nome(construtor) if construtor is not None else None
        if alvo is None:
            return None
        args = tuple(argumentos.named_children) if argumentos is not None else ()
        return Chamada(nome=f"new {alvo}", argumentos=args)
    return None


def _nomes_do_padrao(padrao) -> tuple[str, ...]:
    """Nomes ligados por um alvo, inclusive desestruturacao {a, b: c, ...d}."""
    direto = nome(padrao)
    if direto is not None:
        return (direto,)
    nomes: list[str] = []
    pilha = [padrao]
    while pilha:
        atual = pilha.pop()
        if atual.type in ("identifier", "shorthand_property_identifier_pattern"):
            nomes.append(_texto(atual))
            continue
        if atual.type == "pair_pattern":
            valor = atual.child_by_field_name("value")
            if valor is not None:
                pilha.append(valor)
            continue
        pilha.extend(atual.named_children)
    return tuple(nomes)


def atribuicao(no) -> Atribuicao | None:
    if no.type == "variable_declarator":
        alvo = no.child_by_field_name("name")
        valor = no.child_by_field_name("value")
    elif no.type in ("assignment_expression", "augmented_assignment_expression"):
        alvo = no.child_by_field_name("left")
        valor = no.child_by_field_name("right")
    else:
        return None
    if alvo is None or valor is None:
        return None
    nomes = _nomes_do_padrao(alvo)
    if not nomes:
        return None
    return Atribuicao(alvos=nomes, valor=valor, alvo=alvo)


def texto_literal(no) -> str | None:
    if no.type == "string":
        return "".join(
            _texto(filho) for filho in no.named_children if filho.type == "string_fragment"
        )
    if no.type == "template_string":
        if any(filho.type == "template_substitution" for filho in no.named_children):
            return None
        return "".join(
            _texto(filho) for filho in no.named_children if filho.type == "string_fragment"
        )
    return None


def _chave(no) -> str | None:
    if no.type in ("property_identifier", "identifier"):
        return _texto(no)
    return texto_literal(no)


def pares_de_credencial(no):
    """{ password: "x" } e <Componente apiKey="x" /> (atributo JSX)."""
    if no.type == "pair":
        chave = no.child_by_field_name("key")
        valor = no.child_by_field_name("value")
        if chave is not None and valor is not None:
            texto = _chave(chave)
            if texto is not None:
                return texto, valor
    if no.type == "jsx_attribute" and len(no.named_children) == 2:
        chave, valor = no.named_children
        return _texto(chave), valor
    return None


def saidas_html(no) -> tuple:
    """React: dangerouslySetInnerHTML={{ __html: valor }}."""
    if no.type == "pair":
        chave = no.child_by_field_name("key")
        valor = no.child_by_field_name("value")
        if chave is not None and valor is not None and _chave(chave) == "__html":
            return (valor,)
    return ()


PERFIL_JAVASCRIPT = Perfil(
    linguagem="javascript",
    fronteiras=FRONTEIRAS,
    controle=CONTROLE,
    fontes=FONTES,
    fontes_de_chamada=FONTES_DE_CHAMADA,
    sanitizadores=SANITIZADORES,
    repassadores=REPASSADORES,
    mutadores=MUTADORES,
    sinks=SINKS,
    recomendacoes=RECOMENDACOES,
    nome=nome,
    chamada=chamada,
    atribuicao=atribuicao,
    texto_literal=texto_literal,
    saidas_html=saidas_html,
    pares_de_credencial=pares_de_credencial,
    condicoes=frozenset({"if_statement", "while_statement", "ternary_expression"}),
)
