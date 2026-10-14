"""Perfil PHP: PHP puro (superglobais, mysqli/PDO), Laravel e WordPress.

Construcoes da linguagem que nao sao chamadas na gramatica (`echo`,
`print`, `include`/`require`) sao apresentadas ao motor como `Chamada`s
com esses nomes, para que virem sinks como qualquer funcao.
"""

from __future__ import annotations

from owaspscan.achado import criar_achado
from owaspscan.poliglota.perfil import Atribuicao, Chamada, Perfil, Sink

FONTES: tuple[str, ...] = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER")

FONTES_DE_CHAMADA: tuple[str, ...] = (
    *(
        f"$request.{metodo}"
        for metodo in ("input", "get", "query", "post", "cookie", "header", "all", "route")
    ),
    "request",
    "request().input",
    "request().get",
    "request().query",
    "Request.input",
    "Request.get",
    "Input.get",
    "filter_input",  # sem filtro explicito; com filtro vira "filter_input:filtrado"
)

_NUMERO = frozenset({"CWE-89", "CWE-79", "CWE-22", "CWE-601"})
_HTML = frozenset({"CWE-79"})
_SQL = frozenset({"CWE-89"})

SANITIZADORES: dict[str, frozenset[str]] = {
    "intval": _NUMERO,
    "floatval": _NUMERO,
    "boolval": _NUMERO,
    "abs": _NUMERO,
    "filter_input:filtrado": _NUMERO,
    "htmlspecialchars": _HTML,
    "htmlentities": _HTML,
    "e": _HTML,  # Laravel
    "esc_html": _HTML,  # WordPress
    "esc_attr": _HTML,
    "esc_textarea": _HTML,
    "wp_kses": _HTML,
    "wp_kses_post": _HTML,
    "*.purify": _HTML,  # HTMLPurifier
    "mysqli_real_escape_string": _SQL,
    "*.real_escape_string": _SQL,
    "*.quote": _SQL,  # PDO::quote
    "esc_sql": _SQL,
    "$wpdb.prepare": _SQL,
    "basename": frozenset({"CWE-22"}),
    "urlencode": frozenset({"CWE-79", "CWE-22"}),
    "rawurlencode": frozenset({"CWE-79", "CWE-22"}),
}

REPASSADORES: tuple[str, ...] = (
    "trim",
    "ltrim",
    "rtrim",
    "strtolower",
    "strtoupper",
    "ucfirst",
    "strval",
    "sprintf",
    "implode",
    "join",
    "nl2br",
)

SINKS: tuple[Sink, ...] = (
    Sink(
        cwe="CWE-89",
        padroes=("mysqli_query", "mysqli_multi_query", "mysqli_real_query"),
        descricao="a string SQL de {nome}",
        argumentos=(1,),
    ),
    Sink(
        cwe="CWE-89",
        padroes=("pg_query", "pg_send_query", "sqlite_query"),
        descricao="a string SQL de {nome}",
        argumentos=None,
    ),
    Sink(
        cwe="CWE-89",
        padroes=(
            "mysql_query",
            "*.query",
            "*.exec",
            "*.prepare",
            "*.multi_query",
            "*.real_query",
            *(
                f"DB.{metodo}"
                for metodo in ("raw", "select", "statement", "unprepared", "insert", "update", "delete")
            ),
            "*.whereRaw",
            "*.selectRaw",
            "*.orderByRaw",
            "*.havingRaw",
            "*.groupByRaw",
            *(f"$wpdb.{metodo}" for metodo in ("get_results", "get_row", "get_var", "get_col")),
        ),
        descricao="a string SQL de {nome}",
    ),
    Sink(
        cwe="CWE-79",
        padroes=("echo", "print", "printf", "vprintf"),
        descricao="a saida HTML via {nome}",
        argumentos=None,
    ),
    Sink(
        cwe="CWE-22",
        padroes=(
            "file_get_contents",
            "file_put_contents",
            "fopen",
            "readfile",
            "file",
            "unlink",
            "copy",
            "rename",
            "opendir",
            "scandir",
            "mkdir",
            "rmdir",
            "include",
            "include_once",
            "require",
            "require_once",
            "response().download",
            "response().file",
        ),
        descricao="o caminho de arquivo de {nome}",
    ),
    Sink(
        cwe="CWE-22",
        padroes=("move_uploaded_file",),
        descricao="o destino de {nome}",
        argumentos=(1,),
    ),
    Sink(
        cwe="CWE-601",
        padroes=(
            "header:location",
            "redirect",
            "redirect().to",
            "redirect().away",
            "Redirect.to",
            "Redirect.away",
            "wp_redirect",
        ),
        descricao="o destino de {nome}",
    ),
)

RECOMENDACOES: dict[str, str] = {
    "CWE-89": (
        "Use prepared statement com parametros: $stmt = $pdo->prepare('... WHERE "
        "id = ?'); $stmt->execute([$id]); (mysqli: bind_param). No Laravel, "
        "use o query builder sem *Raw ou passe bindings; no WordPress, "
        "$wpdb->prepare. Nunca concatene dado da requisicao na string SQL."
    ),
    "CWE-79": (
        "Escape na saida: htmlspecialchars($valor, ENT_QUOTES, 'UTF-8'). Em "
        "Blade use {{ }} (nunca {!! !!} com dado do usuario); no WordPress, "
        "esc_html/esc_attr."
    ),
    "CWE-22": (
        "Nunca use dado da requisicao como caminho nem em include/require. "
        "Use basename() para nomes de arquivo, ou realpath() e confira que o "
        "resultado comeca com o diretorio base. Para paginas, mapeie um "
        "identificador para uma lista fixa de arquivos."
    ),
    "CWE-601": (
        "Redirecione apenas para caminhos internos ou hosts de uma lista "
        "permitida (parse_url($destino, PHP_URL_HOST)); no WordPress use "
        "wp_safe_redirect; no Laravel, redirect()->route()."
    ),
    "CWE-798": (
        "Tire o segredo do codigo: leia de getenv()/$_ENV ou do .env do "
        "framework (fora do repositorio), ou de um cofre. Um segredo ja "
        "commitado deve ser considerado vazado: revogue e gere outro."
    ),
}

RECOMENDACAO_COOKIE = (
    "Passe as opcoes do cookie explicitamente: setcookie($nome, $valor, "
    "['secure' => true, 'httponly' => true, 'samesite' => 'Lax']), ou configure "
    "session.cookie_secure e session.cookie_httponly no php.ini."
)
RECOMENDACAO_XXE = (
    "Nao use LIBXML_NOENT nem LIBXML_DTDLOAD ao parsear XML de origem externa; "
    "no PHP 8+ o carregamento de entidades externas ja vem desligado por padrao."
)

FRONTEIRAS = frozenset(
    {
        "function_definition",
        "method_declaration",
        "anonymous_function",
        "anonymous_function_creation_expression",
        "arrow_function",
    }
)

CONTROLE = frozenset(
    {
        "if_statement",
        "else_if_clause",
        "else_clause",
        "for_statement",
        "foreach_statement",
        "while_statement",
        "do_statement",
        "try_statement",
        "catch_clause",
        "switch_statement",
        "conditional_expression",
        "match_expression",
    }
)

_INCLUSOES = {
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
}


def _texto(no) -> str:
    return no.text.decode("utf-8", "replace")


def nome(no) -> str | None:
    tipo = no.type
    if tipo == "variable_name":
        return "$" + _texto(no).lstrip("$")
    if tipo == "name":
        return _texto(no)
    if tipo == "qualified_name":
        return _texto(no).replace("\\", ".").strip(".")
    if tipo == "subscript_expression":
        return nome(no.named_children[0]) if no.named_children else None
    if tipo in ("member_access_expression", "nullsafe_member_access_expression"):
        objeto = no.child_by_field_name("object")
        membro = no.child_by_field_name("name")
        base = nome(objeto) if objeto is not None else None
        if base is None or membro is None:
            return None
        return f"{base}.{_texto(membro).lstrip('$')}"
    if tipo in ("function_call_expression", "member_call_expression",
                "nullsafe_member_call_expression", "scoped_call_expression"):
        alvo = _alvo(no)
        return f"{alvo}()" if alvo is not None else None
    if tipo == "parenthesized_expression":
        return nome(no.named_children[0]) if no.named_children else None
    return None


def _alvo(no) -> str | None:
    if no.type == "function_call_expression":
        funcao = no.child_by_field_name("function")
        return nome(funcao) if funcao is not None else None
    membro = no.child_by_field_name("name")
    if membro is None:
        return None
    if no.type == "scoped_call_expression":
        escopo = no.child_by_field_name("scope")
        base = nome(escopo) if escopo is not None else None
    else:
        objeto = no.child_by_field_name("object")
        base = nome(objeto) if objeto is not None else None
    return f"{base if base is not None else '?'}.{_texto(membro)}"


def _argumentos(no) -> tuple:
    argumentos = no.child_by_field_name("arguments")
    if argumentos is None:
        argumentos = next((f for f in no.named_children if f.type == "arguments"), None)
    if argumentos is None:
        return ()
    # argument -> expressao (o ultimo filho, para pular o nome de argumento nomeado)
    return tuple(
        a.named_children[-1] if a.type == "argument" and a.named_children else a
        for a in argumentos.named_children
    )


def _literal_mais_a_esquerda(no) -> str | None:
    while no.type == "binary_expression":
        no = no.child_by_field_name("left")
    if no.type == "encapsed_string" and no.named_children:
        primeiro = no.named_children[0]
        return _texto(primeiro) if primeiro.type == "string_content" else None
    return texto_literal(no)


def _expressoes_do_echo(no) -> tuple:
    expressoes: list = []
    for filho in no.named_children:
        if filho.type == "sequence_expression":
            expressoes.extend(_expressoes_do_echo(filho))
        else:
            expressoes.append(filho)
    return tuple(expressoes)


def chamada(no) -> Chamada | None:
    tipo = no.type
    if tipo == "function_call_expression":
        alvo = _alvo(no)
        if alvo is None:
            return None
        args = _argumentos(no)
        if alvo == "header" and args:
            prefixo = _literal_mais_a_esquerda(args[0]) or ""
            if prefixo.strip().lower().startswith("location"):
                alvo = "header:location"
        if alvo == "filter_input" and len(args) >= 3:
            alvo = "filter_input:filtrado"
        return Chamada(nome=alvo, argumentos=args)
    if tipo in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
        alvo = _alvo(no)
        if alvo is None:
            return None
        receptor = no.child_by_field_name("object")
        return Chamada(nome=alvo, argumentos=_argumentos(no), receptor=receptor)
    if tipo == "object_creation_expression":
        classe = next(
            (f for f in no.named_children if f.type in ("name", "qualified_name")), None
        )
        if classe is None:
            return None
        return Chamada(nome=f"new {nome(classe)}", argumentos=_argumentos(no))
    if tipo == "echo_statement":
        return Chamada(nome="echo", argumentos=_expressoes_do_echo(no))
    if tipo == "print_intrinsic":
        return Chamada(nome="print", argumentos=tuple(no.named_children))
    if tipo in _INCLUSOES:
        return Chamada(nome=_INCLUSOES[tipo], argumentos=tuple(no.named_children))
    return None


def atribuicao(no) -> Atribuicao | None:
    tipo = no.type
    if tipo in ("assignment_expression", "augmented_assignment_expression"):
        alvo = no.child_by_field_name("left")
        valor = no.child_by_field_name("right")
    elif tipo == "property_element":
        alvo = no.child_by_field_name("name")
        valor = no.child_by_field_name("default_value")
    elif tipo == "const_element" and len(no.named_children) == 2:
        alvo, valor = no.named_children
    else:
        return None
    if alvo is None or valor is None:
        return None
    alvo_nome = nome(alvo)
    if alvo_nome is None:
        return None
    return Atribuicao(alvos=(alvo_nome,), valor=valor, alvo=alvo)


def texto_literal(no) -> str | None:
    if no.type == "string":
        return "".join(_texto(f) for f in no.named_children if f.type == "string_content")
    if no.type == "encapsed_string":
        if any(f.type not in ("string_content", "escape_sequence") for f in no.named_children):
            return None  # interpolacao: nao e literal puro
        return "".join(_texto(f) for f in no.named_children if f.type == "string_content")
    return None


def conversao_numerica(no):
    if no.type != "cast_expression":
        return None
    tipo = no.child_by_field_name("type")
    if tipo is not None and _texto(tipo).lower() in ("int", "integer", "float", "double", "bool", "boolean"):
        return no.child_by_field_name("value")
    return None


_CONEXOES = ("new PDO", "new mysqli", "mysqli_connect", "mysql_connect")


def pares_de_credencial(no):
    """['password' => 'x'], define('DB_PASS', 'x'), new PDO($dsn, 'u', 'senha')."""
    if no.type == "array_element_initializer" and len(no.named_children) == 2:
        chave, valor = no.named_children
        texto = texto_literal(chave)
        return (texto, valor) if texto is not None else None
    encontrada = chamada(no)
    if encontrada is None:
        return None
    args = encontrada.argumentos
    if encontrada.nome == "define" and len(args) == 2:
        texto = texto_literal(args[0])
        return (texto, args[1]) if texto is not None else None
    if encontrada.nome in _CONEXOES and len(args) >= 3:
        return "password", args[2]
    return None


def saidas_html(no) -> tuple:
    """`<?= $x ?>`: a tag curta de echo e seguida de um expression_statement."""
    if no.type != "expression_statement" or not no.named_children:
        return ()
    anterior = no.prev_named_sibling
    if anterior is None:
        return ()
    if anterior.type == "text_interpolation" and anterior.named_children:
        anterior = anterior.named_children[-1]
    if anterior.type == "php_tag" and _texto(anterior) == "<?=":
        return (no.named_children[0],)
    return ()


# -- estruturais -----------------------------------------------------------


def _estrutural(arquivo, no, cwe, severidade, confianca, descricao, recomendacao):
    return criar_achado(
        arquivo=arquivo.arquivo,
        linha=arquivo.linha_de(no),
        cwe=cwe,
        severidade=severidade,
        confianca=confianca,
        trecho=arquivo.trecho_de(no),
        descricao=descricao,
        recomendacao=recomendacao,
    )


def _opcoes(no) -> dict[str, str]:
    """['secure' => true, ...] -> {"secure": "true"}."""
    opcoes: dict[str, str] = {}
    for elemento in no.named_children:
        if elemento.type == "array_element_initializer" and len(elemento.named_children) == 2:
            chave, valor = elemento.named_children
            texto = texto_literal(chave)
            if texto is not None:
                opcoes[texto.lower()] = _texto(valor).lower()
    return opcoes


def _cookies(arquivo, no, encontrada) -> list:
    args = encontrada.argumentos
    if len(args) >= 3 and args[2].type == "array_creation_expression":
        opcoes = _opcoes(args[2])
        flags = {"secure": opcoes.get("secure"), "httponly": opcoes.get("httponly")}
    else:
        flags = {
            "secure": _texto(args[5]).lower() if len(args) > 5 else None,
            "httponly": _texto(args[6]).lower() if len(args) > 6 else None,
        }
    achados = []
    for flag, cwe, efeito in (
        ("secure", "CWE-614", "ele trafega tambem por HTTP sem TLS."),
        ("httponly", "CWE-1004", "JavaScript da pagina (e um XSS) consegue le-lo."),
    ):
        valor = flags[flag]
        if valor == "true":
            continue
        explicito = valor in ("false", "0")
        achados.append(
            _estrutural(
                arquivo, no, cwe, "media", "alta" if explicito else "media",
                f"{encontrada.nome}() "
                + (f"com {flag} desligado explicitamente: " if explicito else f"sem {flag}=true: ")
                + efeito,
                RECOMENDACAO_COOKIE,
            )
        )
    return achados


def estruturais(arquivo, escopos) -> list:
    achados = []
    for escopo in escopos:
        for no in escopo.nos:
            encontrada = chamada(no)
            if encontrada is None:
                continue
            if encontrada.nome in ("setcookie", "setrawcookie") and len(encontrada.argumentos) >= 2:
                achados += _cookies(arquivo, no, encontrada)
            flags_xml = [
                nome(a) for a in encontrada.argumentos if nome(a) in ("LIBXML_NOENT", "LIBXML_DTDLOAD")
            ] + [
                n for a in encontrada.argumentos if a.type == "binary_expression"
                for n in ("LIBXML_NOENT", "LIBXML_DTDLOAD") if n in _texto(a)
            ]
            if flags_xml:
                achados.append(
                    _estrutural(
                        arquivo, no, "CWE-611", "alta", "alta",
                        f"{encontrada.nome}() com {flags_xml[0]}: o parser substitui "
                        "entidades/carrega DTD externo, permitindo ler arquivos "
                        "locais e fazer SSRF com XML malicioso.",
                        RECOMENDACAO_XXE,
                    )
                )
    return achados


PERFIL_PHP = Perfil(
    linguagem="php",
    fronteiras=FRONTEIRAS,
    controle=CONTROLE,
    fontes=FONTES,
    fontes_de_chamada=FONTES_DE_CHAMADA,
    sanitizadores=SANITIZADORES,
    repassadores=REPASSADORES,
    mutadores=(),
    sinks=SINKS,
    recomendacoes=RECOMENDACOES,
    nome=nome,
    chamada=chamada,
    atribuicao=atribuicao,
    texto_literal=texto_literal,
    saidas_html=saidas_html,
    conversao_numerica=conversao_numerica,
    pares_de_credencial=pares_de_credencial,
    condicoes=frozenset({"if_statement", "else_if_clause", "while_statement", "conditional_expression"}),
    estruturais=estruturais,
)
