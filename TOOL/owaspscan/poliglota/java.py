"""Perfil Java: Servlet API, Spring MVC/Security e JDBC/JPA.

Fontes: `request.getParameter(...)` e afins, e parametros de metodos
mapeados do Spring (`@RequestParam`, `@PathVariable`, ... e parametros
`String` sem anotacao, que o Spring tambem preenche a partir da requisicao).

Alem do taint, tres verificacoes estruturais tipicas de Java:
XXE (factory de XML sem hardening), cookie sem Secure/HttpOnly e CSRF
desligado no Spring Security.
"""

from __future__ import annotations

from owaspscan.achado import criar_achado
from owaspscan.poliglota.perfil import Atribuicao, Chamada, Perfil, Sink, casa_algum

_REQUISICOES = ("request", "req", "httpRequest", "servletRequest", "httpServletRequest")

FONTES_DE_CHAMADA: tuple[str, ...] = tuple(
    f"{objeto}.{metodo}"
    for objeto in _REQUISICOES
    for metodo in (
        "getParameter",
        "getParameterValues",
        "getParameterMap",
        "getHeader",
        "getHeaders",
        "getQueryString",
        "getCookies",
        "getInputStream",
        "getReader",
        "getRequestURI",
        "getRequestURL",
        "getPathInfo",
    )
)

ANOTACOES_DE_ENTRADA = frozenset(
    {
        "RequestParam",
        "PathVariable",
        "RequestBody",
        "RequestHeader",
        "CookieValue",
        "ModelAttribute",
        "MatrixVariable",
        # JAX-RS
        "QueryParam",
        "PathParam",
        "FormParam",
        "HeaderParam",
        "CookieParam",
    }
)

ANOTACOES_DE_MAPEAMENTO = frozenset(
    {
        "RequestMapping",
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
    }
)

# Tipos de parametro que o Spring preenche a partir da requisicao sem anotacao.
_TIPOS_TEXTUAIS = frozenset({"String", "String[]", "List<String>"})

_NUMERO = frozenset({"CWE-89", "CWE-79", "CWE-22", "CWE-601"})
_HTML = frozenset({"CWE-79"})

SANITIZADORES: dict[str, frozenset[str]] = {
    "Integer.parseInt": _NUMERO,
    "Integer.valueOf": _NUMERO,
    "Long.parseLong": _NUMERO,
    "Long.valueOf": _NUMERO,
    "Double.parseDouble": _NUMERO,
    "UUID.fromString": _NUMERO,  # formato fixo, sem payload
    "*.encodeForHTML": _HTML,
    "*.encodeForHTMLAttribute": _HTML,
    "*.encodeForJavaScript": _HTML,
    "StringEscapeUtils.escapeHtml4": _HTML,
    "StringEscapeUtils.escapeHtml": _HTML,
    "HtmlUtils.htmlEscape": _HTML,
    "Encode.forHtml": _HTML,
    "Encode.forHtmlContent": _HTML,
    "Encode.forHtmlAttribute": _HTML,
    "Jsoup.clean": _HTML,
    "*.encodeForSQL": frozenset({"CWE-89"}),
    "FilenameUtils.getName": frozenset({"CWE-22"}),
    "*.getFileName": frozenset({"CWE-22"}),
    "URLEncoder.encode": frozenset({"CWE-79", "CWE-22"}),
}

REPASSADORES: tuple[str, ...] = (
    "String.valueOf",
    "String.format",
    "String.join",
    "Paths.get",
    "Path.of",
    "new String",
    "new StringBuilder",
    "new StringBuffer",
    "*.toString",
    "*.trim",
    "*.strip",
    "*.toLowerCase",
    "*.toUpperCase",
    "*.concat",
    "*.append",
    "*.substring",
    "*.resolve",
)

MUTADORES: tuple[str, ...] = ("*.append", "*.add", "*.put")

_JDBC_TEMPLATES = ("jdbcTemplate", "jdbc", "template", "namedParameterJdbcTemplate")
_ESCRITORES = ("out", "writer", "pw", "printWriter")

SINKS: tuple[Sink, ...] = (
    Sink(
        cwe="CWE-89",
        padroes=(
            "*.executeQuery",
            "*.executeUpdate",
            "*.executeLargeUpdate",
            "*.execute",
            "*.addBatch",
            "*.prepareStatement",
            "*.prepareCall",
            "*.createQuery",
            "*.createNativeQuery",
            "*.createSQLQuery",
            "*.queryForObject",
            "*.queryForList",
            "*.queryForMap",
            "*.queryForRowSet",
            "*.batchUpdate",
            *(f"{t}.{m}" for t in _JDBC_TEMPLATES for m in ("query", "update")),
        ),
        descricao="a string SQL de {nome}",
    ),
    Sink(
        cwe="CWE-79",
        padroes=tuple(
            f"{escritor}.{metodo}"
            for escritor in ("*.getWriter()", *_ESCRITORES)
            for metodo in ("print", "println", "write", "printf", "format", "append")
        ),
        descricao="a resposta HTTP via {nome}",
        argumentos=None,
    ),
    Sink(
        cwe="CWE-22",
        padroes=tuple(
            f"new {classe}"
            for classe in (
                "File",
                "FileInputStream",
                "FileOutputStream",
                "FileReader",
                "FileWriter",
                "RandomAccessFile",
                "PrintWriter",
            )
        ),
        descricao="o caminho de arquivo de {nome}",
        argumentos=None,
    ),
    Sink(
        cwe="CWE-22",
        padroes=tuple(
            f"Files.{metodo}"
            for metodo in (
                "readAllBytes",
                "readAllLines",
                "readString",
                "lines",
                "newInputStream",
                "newOutputStream",
                "newBufferedReader",
                "newBufferedWriter",
                "write",
                "writeString",
                "delete",
                "deleteIfExists",
                "copy",
                "move",
            )
        ),
        descricao="o caminho de arquivo de {nome}",
    ),
    Sink(
        cwe="CWE-601",
        padroes=("*.sendRedirect", "new RedirectView"),
        descricao="o destino de {nome}",
    ),
)

RECOMENDACOES: dict[str, str] = {
    "CWE-89": (
        "Use PreparedStatement com placeholders: conn.prepareStatement(\"... WHERE "
        "id = ?\") e stmt.setString(1, valor); no JPA, parametros nomeados "
        "(:id) com setParameter; no JdbcTemplate, query(sql, args). Nunca "
        "concatene dado da requisicao na string SQL/JPQL."
    ),
    "CWE-79": (
        "Escape na saida conforme o contexto: Encode.forHtml (OWASP Java "
        "Encoder) ou HtmlUtils.htmlEscape. Prefira templates que escapam por "
        "padrao (Thymeleaf th:text, JSP <c:out>) a escrever HTML no "
        "response.getWriter() ou devolver String de @ResponseBody."
    ),
    "CWE-22": (
        "Nunca use dado da requisicao como caminho. Extraia so o nome "
        "(FilenameUtils.getName) ou normalize e confine: Path destino = "
        "BASE.resolve(nome).normalize(); if (!destino.startsWith(BASE)) recuse."
    ),
    "CWE-601": (
        "Redirecione apenas para rotas internas ou hosts de uma lista "
        "permitida; valide com URI.create(destino) que host e esquema sao os "
        "esperados. Prefira mapear um identificador para a URL no servidor."
    ),
    "CWE-798": (
        "Tire o segredo do codigo: leia de variavel de ambiente "
        "(System.getenv), de application.properties externo com "
        "${VARIAVEL} ou de um cofre (Vault, AWS Secrets Manager). Um segredo "
        "ja commitado deve ser considerado vazado: revogue e gere outro."
    ),
}

RECOMENDACAO_XXE = (
    "Desligue DTD na factory antes de parsear: "
    "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); "
    "para XMLInputFactory, setProperty(XMLInputFactory.SUPPORT_DTD, false); para "
    "TransformerFactory/SchemaFactory, setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\")."
)
RECOMENDACAO_COOKIE = (
    "Marque o cookie com cookie.setSecure(true) e cookie.setHttpOnly(true) "
    "antes de response.addCookie, ou configure server.servlet.session.cookie."
    "secure/http-only=true no Spring Boot."
)
RECOMENDACAO_CSRF = (
    "Mantenha a protecao CSRF do Spring Security ligada para qualquer rota "
    "autenticada por cookie de sessao. Desligar so e aceitavel em API "
    "stateless autenticada por token no header (Authorization: Bearer)."
)

FRONTEIRAS = frozenset({"method_declaration", "constructor_declaration", "lambda_expression"})

CONTROLE = frozenset(
    {
        "if_statement",
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "try_statement",
        "catch_clause",
        "switch_expression",
        "ternary_expression",
    }
)


def _texto(no) -> str:
    return no.text.decode("utf-8", "replace")


def nome(no) -> str | None:
    tipo = no.type
    if tipo in ("identifier", "this"):
        return _texto(no)
    if tipo == "field_access":
        objeto = no.child_by_field_name("object")
        campo = no.child_by_field_name("field")
        base = nome(objeto) if objeto is not None else None
        if base is None or campo is None:
            return None
        return f"{base}.{_texto(campo)}"
    if tipo == "method_invocation":
        alvo = _alvo_do_metodo(no)
        return f"{alvo}()" if alvo is not None else None
    if tipo == "array_access":
        vetor = no.child_by_field_name("array")
        return nome(vetor) if vetor is not None else None
    if tipo == "parenthesized_expression":
        return nome(no.named_children[0]) if no.named_children else None
    return None


def _alvo_do_metodo(no) -> str | None:
    metodo = no.child_by_field_name("name")
    if metodo is None:
        return None
    objeto = no.child_by_field_name("object")
    if objeto is None:
        return _texto(metodo)
    base = nome(objeto)
    # Objeto que nao e nome ("abc".equals(x), new Foo().bar()): "?" mantem o
    # casamento por sufixo ("*.println") sem inventar um nome.
    return f"{base if base is not None else '?'}.{_texto(metodo)}"


def _nome_do_tipo(no) -> str:
    if no.type == "generic_type" and no.named_children:
        return _nome_do_tipo(no.named_children[0])
    return _texto(no).split(".")[-1]


def chamada(no) -> Chamada | None:
    if no.type == "method_invocation":
        alvo = _alvo_do_metodo(no)
        argumentos = no.child_by_field_name("arguments")
        if alvo is None:
            return None
        args = tuple(argumentos.named_children) if argumentos is not None else ()
        return Chamada(nome=alvo, argumentos=args, receptor=no.child_by_field_name("object"))
    if no.type == "object_creation_expression":
        tipo = no.child_by_field_name("type")
        argumentos = no.child_by_field_name("arguments")
        if tipo is None:
            return None
        args = tuple(argumentos.named_children) if argumentos is not None else ()
        return Chamada(nome=f"new {_nome_do_tipo(tipo)}", argumentos=args)
    return None


def atribuicao(no) -> Atribuicao | None:
    if no.type == "variable_declarator":
        alvo = no.child_by_field_name("name")
        valor = no.child_by_field_name("value")
    elif no.type == "assignment_expression":
        alvo = no.child_by_field_name("left")
        valor = no.child_by_field_name("right")
    else:
        return None
    if alvo is None or valor is None:
        return None
    alvo_nome = nome(alvo)
    if alvo_nome is None:
        return None
    return Atribuicao(alvos=(alvo_nome,), valor=valor, alvo=alvo)


def texto_literal(no) -> str | None:
    if no.type in ("string_literal", "text_block"):
        return "".join(
            _texto(filho) for filho in no.named_children if filho.type == "string_fragment"
        )
    return None


def conversao_numerica(no):
    """(int) x, (long) x: cast para primitivo numerico."""
    if no.type != "cast_expression":
        return None
    tipo = no.child_by_field_name("type")
    if tipo is not None and tipo.type in ("integral_type", "floating_point_type"):
        return no.child_by_field_name("value")
    return None


def pares_de_credencial(no):
    """props.put("password", "x"), ds.setPassword("x"), getConnection(url, u, "x")."""
    if no.type != "method_invocation":
        return None
    alvo = _alvo_do_metodo(no)
    argumentos = no.child_by_field_name("arguments")
    if alvo is None or argumentos is None:
        return None
    args = argumentos.named_children
    metodo = alvo.split(".")[-1]
    if metodo in ("put", "setProperty") and len(args) == 2:
        chave = texto_literal(args[0])
        if chave is not None:
            return chave, args[1]
    if metodo.startswith("set") and len(metodo) > 3 and len(args) == 1:
        return metodo[3:], args[0]
    if casa_algum(("DriverManager.getConnection",), alvo) and len(args) == 3:
        return "password", args[2]
    return None


# -- anotacoes -------------------------------------------------------------


def _anotacoes(no) -> set[str]:
    """Nomes das anotacoes nos modificadores de uma declaracao."""
    nomes: set[str] = set()
    for filho in no.named_children:
        if filho.type != "modifiers":
            continue
        for anotacao in filho.named_children:
            if anotacao.type in ("annotation", "marker_annotation"):
                identificador = anotacao.child_by_field_name("name")
                if identificador is not None:
                    nomes.add(_texto(identificador).split(".")[-1])
    return nomes


def parametros_contaminados(no) -> dict[str, str]:
    if no.type != "method_declaration":
        return {}
    parametros = no.child_by_field_name("parameters")
    if parametros is None:
        return {}
    mapeado = bool(_anotacoes(no) & ANOTACOES_DE_MAPEAMENTO)
    contaminados: dict[str, str] = {}
    for parametro in parametros.named_children:
        if parametro.type != "formal_parameter":
            continue
        identificador = parametro.child_by_field_name("name")
        tipo = parametro.child_by_field_name("type")
        if identificador is None:
            continue
        de_entrada = _anotacoes(parametro) & ANOTACOES_DE_ENTRADA
        if de_entrada:
            contaminados[_texto(identificador)] = "@" + sorted(de_entrada)[0]
        elif mapeado and tipo is not None and _texto(tipo) in _TIPOS_TEXTUAIS:
            contaminados[_texto(identificador)] = "parametro de rota (Spring)"
    return contaminados


def _ancestral(no, tipo: str):
    atual = no.parent
    while atual is not None and atual.type != tipo:
        atual = atual.parent
    return atual


def saidas_html(no) -> tuple:
    """`return texto;` num metodo String de @RestController / @ResponseBody."""
    if no.type != "return_statement" or not no.named_children:
        return ()
    metodo = _ancestral(no, "method_declaration")
    if metodo is None:
        return ()
    tipo = metodo.child_by_field_name("type")
    anotacoes = _anotacoes(metodo)
    if tipo is None or _texto(tipo) != "String" or not anotacoes & ANOTACOES_DE_MAPEAMENTO:
        return ()
    classe = _ancestral(metodo, "class_declaration")
    corpo_da_resposta = "ResponseBody" in anotacoes or (
        classe is not None and "RestController" in _anotacoes(classe)
    )
    return (no.named_children[0],) if corpo_da_resposta else ()


# -- estruturais -----------------------------------------------------------

_FACTORIES_XML = (
    "DocumentBuilderFactory.newInstance",
    "SAXParserFactory.newInstance",
    "XMLInputFactory.newInstance",
    "XMLInputFactory.newFactory",
    "TransformerFactory.newInstance",
    "SchemaFactory.newInstance",
    "new SAXReader",
    "new SAXBuilder",
)

# Literais/constantes que, passados a setFeature/setProperty/setAttribute,
# indicam que alguem endureceu o parser neste arquivo.
_MARCAS_DE_HARDENING = (
    "disallow-doctype-decl",
    "external-general-entities",
    "ACCESS_EXTERNAL_DTD",
    "SUPPORT_DTD",
    "supportDTD",
    "IS_SUPPORTING_EXTERNAL_ENTITIES",
    "FEATURE_SECURE_PROCESSING",
)


def _todas_as_chamadas(escopos):
    for escopo in escopos:
        for no in escopo.nos:
            encontrada = chamada(no)
            if encontrada is not None:
                yield escopo, no, encontrada


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


def _xxe(arquivo, escopos) -> list:
    chamadas = list(_todas_as_chamadas(escopos))
    endurecido = any(
        c.nome.split(".")[-1] in ("setFeature", "setProperty", "setAttribute")
        and any(marca in _texto(a) for a in c.argumentos for marca in _MARCAS_DE_HARDENING)
        for _, _, c in chamadas
    )
    if endurecido:
        return []
    return [
        _estrutural(
            arquivo, no, "CWE-611", "alta", "media",
            f"{c.nome} cria um parser de XML e nenhuma configuracao que desligue "
            "DTD/entidades externas aparece neste arquivo. O padrao do JDK resolve "
            "entidades externas, permitindo ler arquivos locais e fazer SSRF. "
            "Confianca media: o hardening pode estar em outra classe.",
            RECOMENDACAO_XXE,
        )
        for _, no, c in chamadas
        if casa_algum(_FACTORIES_XML, c.nome)
    ]


def _literal_booleano(no) -> str | None:
    return _texto(no) if no.type in ("true", "false") else None


def _cookies(arquivo, escopos) -> list:
    achados = []
    for escopo in escopos:
        criados: dict[str, object] = {}
        flags: dict[tuple[str, str], tuple[str, object]] = {}
        for no in escopo.nos:
            a = atribuicao(no)
            if a is not None:
                c = chamada(a.valor)
                if c is not None and c.nome == "new Cookie":
                    criados[a.alvos[0]] = no
            c = chamada(no)
            if c is not None and c.receptor is not None and len(c.argumentos) == 1:
                metodo = c.nome.split(".")[-1]
                valor = _literal_booleano(c.argumentos[0])
                if metodo in ("setSecure", "setHttpOnly") and valor is not None:
                    flags[(nome(c.receptor) or "", metodo)] = (valor, no)
        for variavel, criacao in criados.items():
            for metodo, cwe, rotulo in (
                ("setSecure", "CWE-614", "Secure"),
                ("setHttpOnly", "CWE-1004", "HttpOnly"),
            ):
                definido = flags.get((variavel, metodo))
                if definido is None:
                    achados.append(
                        _estrutural(
                            arquivo, criacao, cwe, "media", "media",
                            f"Cookie '{variavel}' criado sem {metodo}(true) neste "
                            f"metodo: sem a flag {rotulo}, "
                            + (
                                "ele trafega tambem por HTTP sem TLS."
                                if cwe == "CWE-614"
                                else "JavaScript da pagina (e um XSS) consegue le-lo."
                            ),
                            RECOMENDACAO_COOKIE,
                        )
                    )
                elif definido[0] == "false":
                    achados.append(
                        _estrutural(
                            arquivo, definido[1], cwe, "media", "alta",
                            f"Cookie '{variavel}' com a flag {rotulo} desligada "
                            f"explicitamente ({metodo}(false)).",
                            RECOMENDACAO_COOKIE,
                        )
                    )
    return achados


def _csrf(arquivo, escopos) -> list:
    achados = []
    for _, no, c in _todas_as_chamadas(escopos):
        desligado = casa_algum(("*.csrf().disable",), c.nome) is not None
        if not desligado and casa_algum(("*.csrf", "csrf"), c.nome) and c.argumentos:
            argumento = _texto(c.argumentos[0])
            desligado = argumento.endswith("::disable") or argumento.replace(" ", "").endswith(".disable()")
        if desligado:
            achados.append(
                _estrutural(
                    arquivo, no, "CWE-352", "media", "alta",
                    "Protecao CSRF do Spring Security desligada explicitamente. "
                    "Qualquer rota autenticada por cookie de sessao passa a aceitar "
                    "requisicoes forjadas por outro site.",
                    RECOMENDACAO_CSRF,
                )
            )
    return achados


def estruturais(arquivo, escopos) -> list:
    return [*_xxe(arquivo, escopos), *_cookies(arquivo, escopos), *_csrf(arquivo, escopos)]


PERFIL_JAVA = Perfil(
    linguagem="java",
    fronteiras=FRONTEIRAS,
    controle=CONTROLE,
    fontes=(),
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
    parametros_contaminados=parametros_contaminados,
    saidas_html=saidas_html,
    conversao_numerica=conversao_numerica,
    pares_de_credencial=pares_de_credencial,
    condicoes=frozenset({"if_statement", "while_statement", "ternary_expression"}),
    estruturais=estruturais,
)
