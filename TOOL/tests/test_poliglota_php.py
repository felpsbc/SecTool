"""Fase 24: perfil PHP (superglobais, mysqli/PDO, Laravel, WordPress)."""

import pytest

pytest.importorskip("tree_sitter_php")

from owaspscan.poliglota.fonte import analisar_texto_poliglota
from owaspscan.poliglota.registro import detectar_poliglota


def achados(codigo: str):
    arquivo = analisar_texto_poliglota("<?php\n" + codigo, "php", "x.php")
    return sorted(detectar_poliglota(arquivo), key=lambda a: (a.linha, a.cwe))


def pares(codigo: str):
    return [(a.linha - 1, a.cwe) for a in achados(codigo)]  # linha 1 = codigo[0]


class TestTaint:
    def test_superglobal_concatenada_no_mysqli(self):
        (achado,) = achados('mysqli_query($c, "SELECT " . $_GET["id"]);')
        assert (achado.cwe, achado.confianca) == ("CWE-89", "alta")
        assert "$_GET" in achado.descricao

    def test_interpolacao_em_aspas_duplas(self):
        assert pares('$n = $_POST["n"];\n$pdo->query("SELECT \'$n\'");') == [(2, "CWE-89")]

    def test_primeiro_argumento_do_mysqli_e_a_conexao(self):
        assert pares('mysqli_query($_GET["c"], "SELECT 1");') == []

    def test_prepare_com_execute_e_seguro(self):
        codigo = '$s = $pdo->prepare("SELECT ?");\n$s->execute([$_GET["id"]]);'
        assert pares(codigo) == []

    def test_cast_e_intval_neutralizam(self):
        codigo = '$a = (int) $_GET["a"];\n$b = intval($_GET["b"]);\necho $a . $b;'
        assert pares(codigo) == []

    def test_laravel_request_input(self):
        assert pares('DB::select("SELECT " . $request->input("o"));') == [(1, "CWE-89")]


class TestSaida:
    def test_echo_e_print(self):
        assert pares('echo $_GET["a"];\nprint $_GET["b"];') == [(1, "CWE-79"), (2, "CWE-79")]

    def test_htmlspecialchars_neutraliza(self):
        assert pares('echo htmlspecialchars($_GET["a"]);') == []

    def test_tag_curta_de_echo(self):
        arquivo = analisar_texto_poliglota('<p><?= $_GET["q"] ?></p>', "php", "x.php")
        assert [a.cwe for a in detectar_poliglota(arquivo)] == ["CWE-79"]


class TestCaminhoERedirect:
    def test_include_com_dado_da_requisicao(self):
        assert pares('include $_GET["p"] . ".php";') == [(1, "CWE-22")]

    def test_basename_neutraliza(self):
        assert pares('readfile("/x/" . basename($_GET["f"]));') == []

    def test_header_location_e_redirect(self):
        assert pares('header("Location: " . $_GET["u"]);') == [(1, "CWE-601")]

    def test_outro_header_nao_e_redirect(self):
        assert pares('header("Content-Type: " . $_GET["t"]);') == []


class TestEstruturais:
    def test_setcookie_sem_flags(self):
        assert pares('setcookie("s", $v);') == [(1, "CWE-1004"), (1, "CWE-614")]

    def test_setcookie_com_opcoes_seguras(self):
        assert pares("setcookie('s', $v, ['secure' => true, 'httponly' => true]);") == []

    def test_setcookie_secure_false_e_alta(self):
        (secure,) = [a for a in achados('setcookie("s", $v, 0, "/", "", false, true);')]
        assert (secure.cwe, secure.confianca) == ("CWE-614", "alta")

    def test_libxml_noent_e_xxe(self):
        assert pares("simplexml_load_string($x, null, LIBXML_NOENT);") == [(1, "CWE-611")]


class TestCredenciais:
    def test_variavel_define_e_array(self):
        codigo = (
            '$senha = "s3nh4forte";\n'
            "define('DB_PASSWORD', 'abc12345');\n"
            "$c = ['api_key' => 'k-123456'];"
        )
        assert pares(codigo) == [(1, "CWE-798"), (2, "CWE-798"), (3, "CWE-798")]

    def test_senha_de_conexao_pdo(self):
        assert pares("$p = new PDO($dsn, 'u', 'root123');") == [(1, "CWE-798")]

    def test_getenv_nao_e_credencial(self):
        assert pares("$senha = getenv('DB_PASS');") == []
