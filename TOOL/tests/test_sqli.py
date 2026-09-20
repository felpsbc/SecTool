"""Fase 3: detector de SQL Injection (CWE-89)."""

import pytest

from conftest import DIRETORIO_AMOSTRAS, linhas_de_limitacao, linhas_esperadas
from owaspscan.analisador import analisar_arquivo, analisar_texto
from owaspscan.motor.taint import analisar_taint
from owaspscan.detectores.sqli import DetectorSqlInjection

AMOSTRA_VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_sqli.py"
AMOSTRA_SEGURA = DIRETORIO_AMOSTRAS / "seguro" / "flask_sqli.py"


def detectar(fonte: str, arquivo: str = "app.py"):
    analisado = analisar_texto(fonte, arquivo)
    return DetectorSqlInjection().detectar(analisado, analisar_taint(analisado))


def detectar_arquivo(caminho):
    analisado = analisar_arquivo(caminho, caminho.parent)
    return DetectorSqlInjection().detectar(analisado, analisar_taint(analisado))


class TestAmostraVulneravel:
    def test_detecta_exatamente_as_linhas_do_gabarito(self):
        achados = detectar_arquivo(AMOSTRA_VULNERAVEL)
        assert sorted(a.linha for a in achados) == linhas_esperadas(
            AMOSTRA_VULNERAVEL, "CWE-89"
        )

    def test_achados_saem_classificados_pelo_contrato(self):
        for achado in detectar_arquivo(AMOSTRA_VULNERAVEL):
            assert achado.cwe == "CWE-89"
            assert achado.owasp == "A03:2021 Injection"
            assert achado.vulnerabilidade == "SQL Injection"
            assert achado.severidade == "alta"
            assert achado.arquivo == "flask_sqli.py"

    def test_descricao_nomeia_a_fonte_do_dado(self):
        descricoes = [a.descricao for a in detectar_arquivo(AMOSTRA_VULNERAVEL)]
        assert any("request.args" in d for d in descricoes)
        assert any("request.form" in d for d in descricoes)

    def test_trecho_e_a_chamada_em_uma_linha(self):
        achados = detectar_arquivo(AMOSTRA_VULNERAVEL)
        por_linha = {a.linha: a.trecho for a in achados}
        assert por_linha[22] == (
            'cursor.execute("SELECT * FROM usuarios WHERE id = " + ident)'
        )
        assert all("\n" not in trecho for trecho in por_linha.values())


class TestAusenciaDeFalsoPositivo:
    def test_amostra_segura_nao_gera_achado(self):
        assert detectar_arquivo(AMOSTRA_SEGURA) == []

    def test_query_parametrizada_nao_e_reportada(self):
        achados = detectar(
            "def view(cursor):\n"
            "    ident = request.args['id']\n"
            "    cursor.execute('SELECT * FROM u WHERE id = ?', (ident,))\n"
        )
        assert achados == []

    def test_dado_contaminado_so_na_posicao_de_parametros_nao_e_reportado(self):
        achados = detectar(
            "def view(cursor):\n"
            "    cursor.execute('SELECT * FROM u WHERE id = %s', request.form)\n"
        )
        assert achados == []

    def test_query_literal_nao_e_reportada(self):
        achados = detectar("def view(cursor):\n    cursor.execute('SELECT 1')\n")
        assert achados == []

    def test_concatenacao_apenas_de_literais_nao_e_reportada(self):
        achados = detectar(
            "def view(cursor):\n"
            "    tabela = 'usuarios'\n"
            "    cursor.execute('SELECT * FROM ' + tabela)\n"
        )
        assert achados == []


class TestSinksSuportados:
    @pytest.mark.parametrize(
        "chamada",
        [
            "cursor.execute(consulta)",
            "cursor.executemany(consulta, [])",
            "cursor.executescript(consulta)",
            "conexao.execute(consulta)",
            "self.cursor.execute(consulta)",
            "cursor.execute(sql=consulta)",
        ],
    )
    def test_sinks_db_api(self, chamada):
        achados = detectar(
            "def view(cursor, conexao, self):\n"
            "    consulta = 'SELECT * FROM u WHERE id = ' + request.args['id']\n"
            f"    {chamada}\n"
        )
        assert len(achados) == 1, chamada

    def test_execute_batch_usa_a_segunda_posicao(self):
        achados = detectar(
            "def view(cursor):\n"
            "    consulta = 'INSERT INTO t VALUES ' + request.args['v']\n"
            "    execute_batch(cursor, consulta, [])\n"
        )
        assert len(achados) == 1

    def test_uma_chamada_gera_no_maximo_um_achado(self):
        achados = detectar(
            "def view(cursor):\n"
            "    ident = request.args['id']\n"
            "    cursor.execute('SELECT ' + ident, sql='SELECT ' + ident)\n"
        )
        assert len(achados) == 1

    def test_sink_em_funcao_aninhada_e_atribuido_uma_vez(self):
        achados = detectar(
            "def externa(cursor):\n"
            "    ident = request.args['id']\n"
            "    def interna():\n"
            "        cursor.execute('SELECT ' + ident)\n"
        )
        assert len(achados) == 1
        assert achados[0].linha == 4

    def test_sink_no_nivel_do_modulo_e_detectado(self):
        achados = detectar(
            "consulta = 'SELECT * FROM u WHERE id = ' + request.args['id']\n"
            "cursor.execute(consulta)\n"
        )
        assert len(achados) == 1


class TestLimitacaoDeclarada:
    def test_fluxo_entre_funcoes_nao_e_detectado(self):
        """Falso negativo conhecido e aceito: o motor e intraprocedural.

        Este teste existe para tornar a limitacao mensuravel, nao para
        justifica-la. Se a Fase 10 (interprocedural) for feita, ele muda.
        """
        linhas = {a.linha for a in detectar_arquivo(AMOSTRA_VULNERAVEL)}
        for linha in linhas_de_limitacao(AMOSTRA_VULNERAVEL):
            assert linha not in linhas
