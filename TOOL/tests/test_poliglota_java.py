"""Fase 23: perfil Java (Servlet, Spring MVC/Security, JDBC/JPA)."""

import pytest

pytest.importorskip("tree_sitter_java")

from owaspscan.poliglota.fonte import analisar_texto_poliglota
from owaspscan.poliglota.registro import detectar_poliglota


def achados(corpo: str, cabecalho: str = ""):
    codigo = cabecalho + "class C {\n" + corpo + "\n}\n"
    arquivo = analisar_texto_poliglota(codigo, "java", "C.java")
    return sorted(detectar_poliglota(arquivo), key=lambda a: (a.linha, a.cwe))


def cwes(corpo: str, cabecalho: str = ""):
    return [a.cwe for a in achados(corpo, cabecalho)]


def servlet(corpo: str) -> str:
    return (
        "void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
        + corpo
        + "\n}"
    )


class TestFontes:
    def test_get_parameter_e_fonte(self):
        (achado,) = achados(servlet(
            'stmt.executeQuery("SELECT " + request.getParameter("id"));'
        ))
        assert (achado.cwe, achado.confianca) == ("CWE-89", "alta")
        assert "request.getParameter" in achado.descricao

    def test_anotacao_spring_e_fonte(self):
        corpo = (
            "@GetMapping(\"/x\")\n"
            "List<X> f(@RequestParam String q) {\n"
            '  return jdbcTemplate.queryForList("SELECT " + q);\n'
            "}"
        )
        (achado,) = achados(corpo)
        assert "@RequestParam" in achado.descricao

    def test_parametro_string_de_metodo_mapeado_e_fonte(self):
        corpo = '@GetMapping("/x")\nvoid f(String q) { stmt.execute("SELECT " + q); }'
        assert cwes(corpo) == ["CWE-89"]

    def test_metodo_nao_mapeado_nao_contamina_parametro(self):
        assert cwes('void f(String q) { stmt.execute("SELECT " + q); }') == []


class TestPropagacao:
    def test_stringbuilder_append_contamina(self):
        corpo = servlet(
            "StringBuilder sb = new StringBuilder();\n"
            'sb.append(request.getParameter("x"));\n'
            "stmt.executeQuery(sb.toString());"
        )
        assert cwes(corpo) == ["CWE-89"]

    def test_prepared_statement_com_placeholder_e_seguro(self):
        corpo = servlet(
            'PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id = ?");\n'
            'ps.setString(1, request.getParameter("id"));'
        )
        assert cwes(corpo) == []

    def test_cast_numerico_e_parse_neutralizam(self):
        corpo = servlet(
            'int a = Integer.parseInt(request.getParameter("a"));\n'
            'long b = (long) Double.parseDouble(request.getParameter("b"));\n'
            'stmt.executeQuery("SELECT " + a + b);'
        )
        assert cwes(corpo) == []

    def test_writer_em_variavel(self):
        corpo = servlet(
            "PrintWriter out = response.getWriter();\n"
            'out.println(request.getParameter("x"));'
        )
        assert cwes(corpo) == ["CWE-79"]

    def test_encode_for_html_neutraliza_xss(self):
        corpo = servlet(
            'response.getWriter().print(Encode.forHtml(request.getParameter("x")));'
        )
        assert cwes(corpo) == []


class TestRetornoDoSpring:
    def test_rest_controller_devolvendo_string_e_xss(self):
        codigo = '@GetMapping("/x")\nString f(@RequestParam String n) { return "<b>" + n; }'
        assert cwes(codigo, "@RestController\n") == ["CWE-79"]

    def test_controller_comum_devolve_nome_de_view(self):
        codigo = '@GetMapping("/x")\nString f(@RequestParam String n) { return "pagina"; }'
        assert cwes(codigo, "@Controller\n") == []

    def test_objeto_serializado_em_json_nao_e_xss(self):
        codigo = '@GetMapping("/x")\nProduto f(@RequestParam String n) { return repo.find(n); }'
        assert cwes(codigo, "@RestController\n") == []


class TestEstruturais:
    def test_factory_xml_sem_hardening(self):
        (achado,) = achados("void f() { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); }")
        assert (achado.cwe, achado.severidade, achado.confianca) == ("CWE-611", "alta", "media")

    def test_factory_xml_com_disallow_doctype(self):
        corpo = (
            "void f() {\n"
            "  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            '  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            "}"
        )
        assert cwes(corpo) == []

    def test_cookie_sem_flags(self):
        corpo = 'void f() { Cookie c = new Cookie("s", v); r.addCookie(c); }'
        assert cwes(corpo) == ["CWE-1004", "CWE-614"]

    def test_cookie_com_flag_desligada_e_alta(self):
        corpo = (
            "void f() {\n"
            '  Cookie c = new Cookie("s", v);\n'
            "  c.setSecure(false);\n"
            "  c.setHttpOnly(true);\n"
            "}"
        )
        (achado,) = achados(corpo)
        assert (achado.cwe, achado.confianca, achado.linha) == ("CWE-614", "alta", 4)

    @pytest.mark.parametrize(
        "chamada",
        [
            "http.csrf().disable();",
            "http.csrf(AbstractHttpConfigurer::disable);",
            "http.csrf(c -> c.disable());",
        ],
    )
    def test_csrf_desligado(self, chamada):
        assert cwes("void f(HttpSecurity http) { " + chamada + " }") == ["CWE-352"]


class TestCredenciais:
    def test_campo_constante(self):
        (achado,) = achados('private static final String API_KEY = "abc123def456";')
        assert achado.cwe == "CWE-798"
        assert "abc123def456" not in achado.trecho

    def test_senha_posicional_do_drivermanager_e_setpassword(self):
        corpo = (
            "void f() {\n"
            '  DriverManager.getConnection(url, "u", "s3nh4");\n'
            '  ds.setPassword("outra-s3nh4");\n'
            "}"
        )
        assert cwes(corpo) == ["CWE-798", "CWE-798"]

    def test_getenv_nao_e_credencial(self):
        assert cwes('String DB_PASSWORD = System.getenv("DB_PASSWORD");') == []
