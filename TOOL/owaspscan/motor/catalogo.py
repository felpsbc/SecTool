"""Catalogo declarativo de fontes nao confiaveis.

Este modulo e dado, nao logica: adicionar um framework deve ser acrescentar
entradas aqui, sem tocar em `taint.py`. Sinks e sanitizadores entram nas
fases seguintes, no mesmo formato.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FonteDeDados:
    """Uma expressao cujo valor vem do usuario e nao e confiavel."""

    rotulo: str  # "request.args"
    framework: str  # "flask"
    descricao: str


# Flask. O acesso pode ser direto (`request.args`), por indice
# (`request.args["id"]`) ou por metodo (`request.args.get("id")`); todos sao
# reconhecidos porque a checagem e por prefixo do nome pontilhado.
FONTES_FLASK: tuple[FonteDeDados, ...] = (
    FonteDeDados("request.args", "flask", "parametros da query string"),
    FonteDeDados("request.form", "flask", "campos de formulario"),
    FonteDeDados("request.values", "flask", "query string e formulario combinados"),
    FonteDeDados("request.json", "flask", "corpo JSON da requisicao"),
    FonteDeDados("request.get_json", "flask", "corpo JSON da requisicao"),
    FonteDeDados("request.data", "flask", "corpo bruto da requisicao"),
    FonteDeDados("request.get_data", "flask", "corpo bruto da requisicao"),
    FonteDeDados("request.files", "flask", "arquivos enviados"),
    FonteDeDados("request.cookies", "flask", "cookies da requisicao"),
    FonteDeDados("request.headers", "flask", "cabecalhos da requisicao"),
    FonteDeDados("request.query_string", "flask", "query string bruta"),
    FonteDeDados("request.view_args", "flask", "parametros da rota"),
    FonteDeDados("request.full_path", "flask", "caminho com query string"),
    FonteDeDados("request.url", "flask", "URL completa da requisicao"),
    FonteDeDados("request.referrer", "flask", "cabecalho Referer"),
)


@dataclass(frozen=True)
class SinkSql:
    """Chamada que entrega uma string ao banco como comando SQL.

    `posicoes` e `palavras_chave` listam apenas os argumentos interpretados
    como SQL. O argumento de parametros (2o posicional de `execute`) fica
    fora de proposito: e a defesa correta, nao o sink.
    """

    metodo: str  # "execute"
    posicoes: tuple[int, ...]  # (0,)
    palavras_chave: tuple[str, ...]  # ("sql", "query", "operation")
    descricao: str


# DB-API 2.0 (PEP 249): cobre sqlite3, psycopg2, MySQLdb, pymysql e o SQL
# cru usado em aplicacoes Flask. Nao e especifico de framework.
SINKS_SQL: tuple[SinkSql, ...] = (
    SinkSql("execute", (0,), ("sql", "query", "operation"), "cursor.execute (DB-API)"),
    SinkSql(
        "executemany",
        (0,),
        ("sql", "query", "operation"),
        "cursor.executemany (DB-API)",
    ),
    SinkSql("executescript", (0,), ("sql_script",), "cursor.executescript (sqlite3)"),
    SinkSql("execute_batch", (1,), ("sql",), "psycopg2.extras.execute_batch"),
    SinkSql("execute_values", (1,), ("sql",), "psycopg2.extras.execute_values"),
)


@dataclass(frozen=True)
class Sanitizador:
    """Chamada que torna um valor seguro — para algumas CWEs, nao para todas.

    `cwes` e o qualificador que evita o erro classico de tratar sanitizacao
    como absoluta: html.escape() defende XSS e nao defende SQL Injection.
    """

    rotulo: str  # nome pontilhado da chamada, ex. "html.escape"
    cwes: frozenset[str]
    descricao: str


_NEUTRALIZA_INJECAO = frozenset({"CWE-89", "CWE-79"})
_NEUTRALIZA_XSS = frozenset({"CWE-79"})

# Casts que trocam o tipo do valor: o resultado deixa de ser string
# arbitraria controlada pelo atacante. Nao defendem IDOR — um inteiro
# continua podendo ser o identificador de outro usuario.
SANITIZADORES: tuple[Sanitizador, ...] = (
    Sanitizador("int", _NEUTRALIZA_INJECAO, "conversao para inteiro"),
    Sanitizador("float", _NEUTRALIZA_INJECAO, "conversao para ponto flutuante"),
    Sanitizador("bool", _NEUTRALIZA_INJECAO, "conversao para booleano"),
    Sanitizador("uuid.UUID", _NEUTRALIZA_INJECAO, "conversao para UUID"),
    Sanitizador("UUID", _NEUTRALIZA_INJECAO, "conversao para UUID"),
    Sanitizador("decimal.Decimal", _NEUTRALIZA_INJECAO, "conversao para Decimal"),
    Sanitizador("Decimal", _NEUTRALIZA_INJECAO, "conversao para Decimal"),
    # Escapes de HTML: defendem XSS, nao defendem SQL Injection.
    Sanitizador("escape", _NEUTRALIZA_XSS, "escape de HTML"),
    Sanitizador("html.escape", _NEUTRALIZA_XSS, "escape de HTML"),
    Sanitizador("markupsafe.escape", _NEUTRALIZA_XSS, "escape de HTML"),
    Sanitizador("flask.escape", _NEUTRALIZA_XSS, "escape de HTML"),
    Sanitizador("django.utils.html.escape", _NEUTRALIZA_XSS, "escape de HTML"),
    Sanitizador("bleach.clean", _NEUTRALIZA_XSS, "sanitizacao de HTML (bleach)"),
)

# Manipulacao de string: nao sanitiza, mas tambem nao e caixa-preta. Passar
# por aqui nao rebaixa a confianca do achado (ver motor/confianca.py).
OPERACOES_DE_STRING: frozenset[str] = frozenset(
    {
        "str",
        "format",
        "format_map",
        "join",
        "strip",
        "lstrip",
        "rstrip",
        "upper",
        "lower",
        "title",
        "capitalize",
        "casefold",
        "replace",
        "encode",
        "decode",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "removeprefix",
        "removesuffix",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "get",
        "getlist",
        "list",
        "tuple",
        "next",
        "iter",
    }
)


@dataclass(frozen=True)
class SinkXss:
    """Chamada que entrega uma string ao navegador como HTML.

    `categoria` separa o bypass explicito do auto-escape (vale em qualquer
    contexto) da construcao de resposta (so vale dentro de uma view de rota).
    """

    rotulo: str  # nome da funcao/metodo chamado
    posicoes: tuple[int, ...]
    palavras_chave: tuple[str, ...]
    categoria: str  # "bypass" | "resposta"
    descricao: str


SINKS_XSS: tuple[SinkXss, ...] = (
    SinkXss(
        "render_template_string",
        (0,),
        ("source",),
        "bypass",
        "render_template_string (template montado em tempo de execucao)",
    ),
    SinkXss("Markup", (0,), (), "bypass", "Markup (marca HTML como confiavel)"),
    SinkXss("mark_safe", (0,), (), "bypass", "mark_safe (desativa o auto-escape)"),
    SinkXss("format_html", (0,), (), "bypass", "format_html com formato dinamico"),
    SinkXss("make_response", (0,), (), "resposta", "make_response com HTML montado"),
    SinkXss("HttpResponse", (0,), ("content",), "resposta", "HttpResponse com HTML montado"),
    SinkXss("Response", (0,), ("response",), "resposta", "Response com HTML montado"),
)

# Respostas que nao sao interpretadas como HTML pelo navegador. Retornar
# dado contaminado por aqui nao e XSS — sem esta lista, toda API JSON viraria
# falso positivo.
RESPOSTAS_NAO_HTML: frozenset[str] = frozenset(
    {
        "jsonify",
        "JsonResponse",
        "dumps",
        "json_response",
        "send_file",
        "send_from_directory",
        "redirect",
        "url_for",
        "abort",
        "FileResponse",
        "StreamingHttpResponse",
    }
)

# Respostas renderizadas por template engine com auto-escape ligado. O dado
# contaminado vai como variavel de contexto e e escapado pelo Jinja2/Django.
# Limitacao declarada: nao analisamos os arquivos de template, entao um
# `|safe` dentro do .html nao e visto pela ferramenta.
RESPOSTAS_COM_AUTO_ESCAPE: frozenset[str] = frozenset(
    {
        "render_template",
        "stream_template",
        "render",
        "render_to_response",
        "render_to_string",
        "TemplateResponse",
    }
)

# Decoradores que marcam uma funcao como view de rota (Flask e Django REST).
DECORADORES_DE_ROTA: frozenset[str] = frozenset(
    {"route", "get", "post", "put", "patch", "delete", "websocket"}
)


# --- IDOR (CWE-639) -------------------------------------------------------

# Metodos de consulta que recuperam um objeto pelo identificador.
METODOS_DE_LOOKUP: frozenset[str] = frozenset(
    {"get", "filter", "filter_by", "get_or_404", "first_or_404", "one_or_none"}
)

# Funcoes de lookup chamadas diretamente (atalhos do Django).
FUNCOES_DE_LOOKUP: frozenset[str] = frozenset(
    {"get_object_or_404", "get_list_or_404"}
)

# Receptores que indicam consulta a modelo: Pedido.query.get, Pedido.objects.filter.
RECEPTORES_DE_CONSULTA: frozenset[str] = frozenset({"query", "objects", "session"})

# Nomes de campo que identificam um objeto.
CAMPOS_DE_ID: frozenset[str] = frozenset({"pk", "id", "uuid", "identificador"})

# Campos que amarram a consulta ao dono do recurso: presenca deles indica
# que o controle de acesso foi feito na propria query.
CAMPOS_DE_DONO: frozenset[str] = frozenset(
    {
        "user",
        "user_id",
        "owner",
        "owner_id",
        "usuario",
        "usuario_id",
        "dono",
        "dono_id",
        "cliente",
        "cliente_id",
        "created_by",
        "author",
        "autor",
        "account",
        "conta",
        "tenant",
    }
)

# Expressoes que representam o usuario autenticado da sessao.
IDENTIDADES_AUTENTICADAS: frozenset[str] = frozenset(
    {
        "current_user",
        "request.user",
        "g.user",
        "session",
        "flask_login.current_user",
        "self.request.user",
    }
)

# Decoradores que indicam AUTORIZACAO (permissao sobre o recurso).
# `login_required` fica de fora de proposito: autenticar nao e autorizar.
DECORADORES_DE_AUTORIZACAO: frozenset[str] = frozenset(
    {
        "permission_required",
        "permissions_required",
        "has_permission",
        "user_passes_test",
        "owner_required",
        "requires_permission",
        "authorize",
        "authorized",
        "staff_member_required",
        "admin_required",
        "require_role",
        "roles_required",
    }
)


def tem_decorador_de_autorizacao(no: ast.AST) -> bool:
    """A view declara checagem de permissao por decorador?"""
    for decorador in getattr(no, "decorator_list", []):
        alvo = decorador.func if isinstance(decorador, ast.Call) else decorador
        pontilhado = nome_pontilhado(alvo)
        if pontilhado and pontilhado.split(".")[-1] in DECORADORES_DE_AUTORIZACAO:
            return True
    return False


def nomes_de_parametros_de_rota(no: ast.AST) -> frozenset[str]:
    """Parametros da view que vem da URL.

    Prefere os nomes declarados na regra da rota (`/pedido/<int:pedido_id>`);
    sem regra literal, assume os parametros da funcao, exceto os do framework.
    """
    if not e_view_de_rota(no):
        return frozenset()

    da_regra: set[str] = set()
    for decorador in getattr(no, "decorator_list", []):
        if not isinstance(decorador, ast.Call):
            continue
        for argumento in decorador.args:
            if not (isinstance(argumento, ast.Constant) and isinstance(argumento.value, str)):
                continue
            for pedaco in argumento.value.split("<")[1:]:
                nome = pedaco.split(">")[0]
                da_regra.add(nome.split(":")[-1])
    if da_regra:
        return frozenset(da_regra)

    argumentos = getattr(no, "args", None)
    if argumentos is None:
        return frozenset()
    todos = [*argumentos.posonlyargs, *argumentos.args, *argumentos.kwonlyargs]
    return frozenset(
        arg.arg for arg in todos if arg.arg not in {"self", "cls", "request"}
    )


def e_view_de_rota(no: ast.AST) -> bool:
    """A funcao esta exposta como rota HTTP?"""
    for decorador in getattr(no, "decorator_list", []):
        alvo = decorador.func if isinstance(decorador, ast.Call) else decorador
        pontilhado = nome_pontilhado(alvo)
        if pontilhado and pontilhado.split(".")[-1] in DECORADORES_DE_ROTA:
            return True
    return False


@dataclass(frozen=True)
class Catalogo:
    """Conjunto de fontes, sinks e sanitizadores ativos em uma analise."""

    fontes: tuple[FonteDeDados, ...] = field(default=FONTES_FLASK)
    sinks_sql: tuple[SinkSql, ...] = field(default=SINKS_SQL)
    sinks_xss: tuple[SinkXss, ...] = field(default=SINKS_XSS)
    sanitizadores: tuple[Sanitizador, ...] = field(default=SANITIZADORES)
    operacoes_de_string: frozenset[str] = field(default=OPERACOES_DE_STRING)
    respostas_nao_html: frozenset[str] = field(default=RESPOSTAS_NAO_HTML)
    respostas_com_auto_escape: frozenset[str] = field(
        default=RESPOSTAS_COM_AUTO_ESCAPE
    )

    def sanitizador_para(self, no: ast.AST) -> Sanitizador | None:
        """Casa a funcao chamada com um sanitizador declarado."""
        if not isinstance(no, ast.Call):
            return None
        pontilhado = nome_pontilhado(no.func)
        if pontilhado is None:
            return None
        for sanitizador in self.sanitizadores:
            if sanitizador.rotulo == pontilhado:
                return sanitizador
        return None

    def neutraliza(self, rotulos: frozenset[str], cwe: str) -> bool:
        """A CWE esta neutralizada por algum dos sanitizadores aplicados?"""
        for sanitizador in self.sanitizadores:
            if sanitizador.rotulo in rotulos and cwe in sanitizador.cwes:
                return True
        return False

    def e_operacao_de_string(self, no: ast.AST) -> bool:
        """A chamada e manipulacao de string, e nao uma funcao opaca?"""
        if not isinstance(no, ast.Call):
            return False
        func = no.func
        if isinstance(func, ast.Attribute):
            return func.attr in self.operacoes_de_string
        if isinstance(func, ast.Name):
            return func.id in self.operacoes_de_string
        return False

    def sink_sql_para(self, no: ast.AST) -> SinkSql | None:
        """Casa uma chamada com um sink SQL pelo nome do metodo invocado."""
        if not isinstance(no, ast.Call):
            return None
        func = no.func
        metodo = func.attr if isinstance(func, ast.Attribute) else (
            func.id if isinstance(func, ast.Name) else None
        )
        if metodo is None:
            return None
        for sink in self.sinks_sql:
            if sink.metodo == metodo:
                return sink
        return None

    def sink_xss_para(self, no: ast.AST) -> SinkXss | None:
        """Casa uma chamada com um sink de XSS pelo nome invocado."""
        if not isinstance(no, ast.Call):
            return None
        pontilhado = nome_pontilhado(no.func)
        if pontilhado is None:
            return None
        chamado = pontilhado.split(".")[-1]
        for sink in self.sinks_xss:
            if sink.rotulo == chamado:
                return sink
        return None

    def e_resposta_segura(self, no: ast.AST) -> bool:
        """A expressao e uma resposta que nao expoe HTML nao escapado?

        Cobre dois casos: resposta que o navegador nao interpreta como HTML
        (JSON, download, redirect) e template renderizado com auto-escape.
        """
        if not isinstance(no, ast.Call):
            return False
        pontilhado = nome_pontilhado(no.func)
        if pontilhado is None:
            return False
        chamado = pontilhado.split(".")[-1]
        return (
            chamado in self.respostas_nao_html
            or chamado in self.respostas_com_auto_escape
        )

    def lookup_de_objeto(self, no: ast.AST) -> str | None:
        """A chamada recupera um objeto do banco pelo identificador?

        Devolve a descricao do lookup, ou None. Exige receptor de consulta
        (`Pedido.query`, `Pedido.objects`, `session.query(...)`) para que um
        `.get()` de dicionario nao dispare candidato.
        """
        if not isinstance(no, ast.Call):
            return None
        func = no.func
        if isinstance(func, ast.Name):
            if func.id in FUNCOES_DE_LOOKUP:
                return f"{func.id}()"
            return None
        if not isinstance(func, ast.Attribute):
            return None
        if func.attr not in METODOS_DE_LOOKUP:
            return None

        receptor = func.value
        pontilhado = nome_pontilhado(receptor)
        if pontilhado is not None:
            segmentos = pontilhado.split(".")
            if segmentos[-1] in RECEPTORES_DE_CONSULTA:
                return f"{pontilhado}.{func.attr}()"
            return None
        # `session.query(Pedido).get(x)`: o receptor e a propria chamada query().
        if isinstance(receptor, ast.Call):
            interno = nome_pontilhado(receptor.func)
            if interno and interno.split(".")[-1] == "query":
                return f"{interno}(...).{func.attr}()"
        return None

    def argumentos_de_identificador(self, no: ast.Call, lookup: str) -> list[ast.AST]:
        """Argumentos da chamada que identificam o objeto procurado."""
        encontrados: list[ast.AST] = []
        if no.args and (
            lookup.endswith("get()")
            or lookup.endswith("get_or_404()")
            or lookup.startswith("get_object_or_404")
            or lookup.startswith("get_list_or_404")
        ):
            # Primeiro posicional de get()/get_or_404() e a chave primaria;
            # em get_object_or_404(Modelo, pk) o primeiro e o modelo.
            posicionais = no.args[1:] if lookup.startswith("get_") and len(no.args) > 1 else no.args
            encontrados.extend(posicionais)
        for palavra in no.keywords:
            if palavra.arg is None:
                continue
            nome = palavra.arg.split("__")[0]
            if nome in CAMPOS_DE_ID or nome.endswith("_id"):
                encontrados.append(palavra.value)
        return encontrados

    def tem_filtro_de_dono(self, no: ast.Call) -> bool:
        """A consulta amarra o objeto ao usuario autenticado?"""
        for palavra in no.keywords:
            if palavra.arg and palavra.arg.split("__")[0] in CAMPOS_DE_DONO:
                return True
        for expressao in [*no.args, *(p.value for p in no.keywords)]:
            for interno in ast.walk(expressao):
                pontilhado = nome_pontilhado(interno)
                if pontilhado and (
                    pontilhado in IDENTIDADES_AUTENTICADAS
                    or pontilhado.split(".")[0] in {"current_user", "g"}
                ):
                    return True
                if isinstance(interno, ast.Attribute) and interno.attr in CAMPOS_DE_DONO:
                    return True
        return False

    def argumentos_de(self, no: ast.Call, posicoes, palavras_chave) -> list[ast.AST]:
        """Argumentos de uma chamada nas posicoes/palavras indicadas."""
        encontrados: list[ast.AST] = []
        for posicao in posicoes:
            if posicao < len(no.args):
                encontrados.append(no.args[posicao])
        for palavra in no.keywords:
            if palavra.arg in palavras_chave:
                encontrados.append(palavra.value)
        return encontrados

    def argumentos_de_sql(self, no: ast.Call, sink: SinkSql) -> list[ast.AST]:
        """Argumentos da chamada que sao interpretados como SQL."""
        encontrados: list[ast.AST] = []
        for posicao in sink.posicoes:
            if posicao < len(no.args):
                encontrados.append(no.args[posicao])
        for palavra in no.keywords:
            if palavra.arg in sink.palavras_chave:
                encontrados.append(palavra.value)
        return encontrados

    def frameworks(self) -> frozenset[str]:
        return frozenset(fonte.framework for fonte in self.fontes)

    def fonte_para(self, nome_pontilhado: str | None) -> FonteDeDados | None:
        """Casa um nome pontilhado com a fonte mais especifica do catalogo.

        `request.args.get` casa com a fonte `request.args`; `request.argsx`
        nao casa, porque a comparacao respeita a fronteira do ponto.
        """
        if not nome_pontilhado:
            return None
        candidatas = [
            fonte
            for fonte in self.fontes
            if nome_pontilhado == fonte.rotulo
            or nome_pontilhado.startswith(fonte.rotulo + ".")
        ]
        if not candidatas:
            return None
        return max(candidatas, key=lambda fonte: len(fonte.rotulo))


CATALOGO_PADRAO = Catalogo()


def nome_pontilhado(no: ast.AST) -> str | None:
    """Reconstroi `a.b.c` a partir de uma cadeia Name/Attribute.

    Devolve None para qualquer outra forma de expressao.
    """
    partes: list[str] = []
    atual: ast.AST = no
    while isinstance(atual, ast.Attribute):
        partes.append(atual.attr)
        atual = atual.value
    if not isinstance(atual, ast.Name):
        return None
    partes.append(atual.id)
    return ".".join(reversed(partes))
