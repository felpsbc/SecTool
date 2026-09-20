"""Fase 4: sanitizacao por CWE e calibracao de confianca pela procedencia."""

import pytest

from owaspscan.analisador import analisar_texto
from owaspscan.detectores.sqli import DetectorSqlInjection
from owaspscan.motor.catalogo import CATALOGO_PADRAO
from owaspscan.motor.confianca import confianca_para, procedencias_relevantes
from owaspscan.motor.taint import Procedencia, analisar_taint, escopo_de

MOLDE = "def view(c):\n    ident = {expressao}\n    c.execute('SELECT * FROM u WHERE id = ' + str(ident))\n"


def achados(fonte: str):
    analisado = analisar_texto(fonte, "app.py")
    return DetectorSqlInjection().detectar(analisado, analisar_taint(analisado))


def achados_do_molde(expressao: str):
    return achados(MOLDE.format(expressao=expressao))


class TestSanitizacaoRemoveOAchado:
    @pytest.mark.parametrize(
        "expressao",
        [
            "int(request.args['id'])",
            "float(request.args['id'])",
            "uuid.UUID(request.args['id'])",
            "UUID(request.args['id'])",
            "Decimal(request.args['id'])",
        ],
    )
    def test_cast_neutraliza_sqli(self, expressao):
        assert achados_do_molde(expressao) == [], expressao

    def test_sanitizacao_sobrevive_a_cadeia_de_variaveis(self):
        assert (
            achados(
                "def view(c):\n"
                "    bruto = request.args['id']\n"
                "    ident = int(bruto)\n"
                "    texto = str(ident)\n"
                "    c.execute('SELECT * FROM u WHERE id = ' + texto)\n"
            )
            == []
        )

    def test_mesmo_fluxo_sem_sanitizador_e_reportado(self):
        # Contraprova do teste acima: a unica diferenca e o int().
        resultado = achados_do_molde("request.args['id']")
        assert len(resultado) == 1
        assert resultado[0].confianca == "alta"


class TestSanitizacaoEEspecificaPorCwe:
    def test_escape_de_html_nao_protege_contra_sqli(self):
        """O erro classico que a Fase 4 existe para nao cometer."""
        resultado = achados_do_molde("escape(request.args['id'])")
        assert len(resultado) == 1
        assert resultado[0].cwe == "CWE-89"

    @pytest.mark.parametrize(
        "rotulo, cwe, esperado",
        [
            ("int", "CWE-89", True),
            ("int", "CWE-79", True),
            ("int", "CWE-639", False),
            ("html.escape", "CWE-79", True),
            ("html.escape", "CWE-89", False),
            ("bleach.clean", "CWE-79", True),
        ],
    )
    def test_catalogo_declara_o_alcance_de_cada_sanitizador(self, rotulo, cwe, esperado):
        assert CATALOGO_PADRAO.neutraliza(frozenset({rotulo}), cwe) is esperado

    def test_funcao_desconhecida_nao_conta_como_sanitizador(self):
        resultado = achados_do_molde("minha_limpeza(request.args['id'])")
        assert len(resultado) == 1

    def test_procedencias_relevantes_descarta_so_o_que_neutraliza(self):
        limpa = Procedencia("request.args", frozenset({"int"}))
        suja = Procedencia("request.form")
        conjunto = frozenset({limpa, suja})
        assert procedencias_relevantes(conjunto, "CWE-89", CATALOGO_PADRAO) == frozenset(
            {suja}
        )


class TestSanitizacaoParcial:
    def test_um_ramo_sanitizado_e_outro_nao_continua_sendo_achado(self):
        resultado = achados(
            "def view(c):\n"
            "    if condicao:\n"
            "        ident = int(request.args['id'])\n"
            "    else:\n"
            "        ident = request.args['id']\n"
            "    c.execute('SELECT * FROM u WHERE id = ' + str(ident))\n"
        )
        assert len(resultado) == 1
        assert resultado[0].confianca == "media"


class TestCalibracaoDeConfianca:
    @pytest.mark.parametrize(
        "corpo, esperado",
        [
            ("    c.execute('S ' + request.args['id'])", "alta"),
            ("    i = request.args['id']\n    c.execute('S ' + i)", "alta"),
            ("    i = request.args['id']\n    c.execute('S {}'.format(i))", "alta"),
            ("    i = request.args['id']\n    c.execute(f'S {i}')", "alta"),
            ("    i = request.args['id'].strip()\n    c.execute('S ' + i)", "alta"),
            ("    i = montar(request.args['id'])\n    c.execute('S ' + i)", "media"),
            (
                "    i = '1'\n    if x:\n        i = request.args['id']\n"
                "    c.execute('S ' + i)",
                "media",
            ),
            (
                "    for i in request.args.getlist('ids'):\n        c.execute('S ' + i)",
                "media",
            ),
        ],
    )
    def test_confianca_reflete_a_procedencia(self, corpo, esperado):
        resultado = achados(f"def view(c, x):\n{corpo}\n")
        assert len(resultado) == 1, corpo
        assert resultado[0].confianca == esperado, corpo

    def test_confianca_media_explica_o_motivo_na_descricao(self):
        resultado = achados(
            "def view(c):\n"
            "    i = montar(request.args['id'])\n"
            "    c.execute('S ' + i)\n"
        )
        assert "funcao nao analisada" in resultado[0].descricao

    def test_confianca_alta_nao_carrega_ressalva(self):
        resultado = achados(
            "def view(c):\n    c.execute('S ' + request.args['id'])\n"
        )
        assert "Confianca reduzida" not in resultado[0].descricao

    def test_cadeia_limpa_vence_cadeia_incerta(self):
        # Basta uma cadeia direta para sustentar confianca alta.
        procedencias = frozenset(
            {
                Procedencia("request.args"),
                Procedencia("request.form", via_chamada=True),
            }
        )
        assert confianca_para(procedencias) == "alta"

    def test_amostra_segura_continua_sem_achados_apos_sanitizacao(self):
        from conftest import DIRETORIO_AMOSTRAS
        from owaspscan.analisador import analisar_arquivo

        caminho = DIRETORIO_AMOSTRAS / "seguro" / "flask_sqli.py"
        analisado = analisar_arquivo(caminho, caminho.parent)
        assert DetectorSqlInjection().detectar(analisado, analisar_taint(analisado)) == []
