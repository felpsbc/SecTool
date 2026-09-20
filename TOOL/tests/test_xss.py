"""Fase 5: detector de Cross-Site Scripting refletido (CWE-79)."""

import pytest

from conftest import DIRETORIO_AMOSTRAS, linhas_esperadas
from owaspscan.analisador import analisar_arquivo, analisar_texto
from owaspscan.detectores.xss import DetectorXss
from owaspscan.motor.taint import analisar_taint

AMOSTRA_VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_xss.py"
AMOSTRA_SEGURA = DIRETORIO_AMOSTRAS / "seguro" / "flask_xss.py"
SQLI_VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_sqli.py"

ROTA = '@app.route("/x")\ndef view():\n{corpo}\n'


def detectar(fonte: str, arquivo: str = "app.py"):
    analisado = analisar_texto(fonte, arquivo)
    return DetectorXss().detectar(analisado, analisar_taint(analisado))


def detectar_em_rota(corpo: str):
    return detectar(ROTA.format(corpo=corpo))


def detectar_arquivo(caminho):
    analisado = analisar_arquivo(caminho, caminho.parent)
    return DetectorXss().detectar(analisado, analisar_taint(analisado))


class TestAmostraVulneravel:
    def test_detecta_exatamente_as_linhas_do_gabarito(self):
        achados = detectar_arquivo(AMOSTRA_VULNERAVEL)
        assert sorted(a.linha for a in achados) == linhas_esperadas(
            AMOSTRA_VULNERAVEL, "CWE-79"
        )

    def test_achados_saem_classificados_pelo_contrato(self):
        for achado in detectar_arquivo(AMOSTRA_VULNERAVEL):
            assert achado.cwe == "CWE-79"
            assert achado.owasp == "A03:2021 Injection"
            assert achado.vulnerabilidade == "Cross-Site Scripting"
            assert achado.severidade == "media"

    def test_um_achado_por_sink(self):
        achados = detectar_arquivo(AMOSTRA_VULNERAVEL)
        assert len(achados) == len({a.linha for a in achados})


class TestBypassDeAutoEscape:
    @pytest.mark.parametrize(
        "chamada",
        [
            "Markup('<p>' + texto + '</p>')",
            "mark_safe('<p>' + texto + '</p>')",
            "render_template_string('<p>' + texto + '</p>')",
            "format_html('<p>' + texto + '</p>')",
        ],
    )
    def test_bypass_explicito_e_reportado(self, chamada):
        achados = detectar(
            "def helper():\n"
            "    texto = request.args['t']\n"
            f"    return {chamada}\n"
        )
        assert len(achados) == 1, chamada

    def test_bypass_vale_fora_de_view_de_rota(self):
        achados = detectar(
            "def helper():\n    return mark_safe('<b>' + request.args['t'] + '</b>')\n"
        )
        assert len(achados) == 1

    def test_escape_antes_do_bypass_remove_o_achado(self):
        achados = detectar(
            "def helper():\n"
            "    return Markup('<p>' + escape(request.args['t']) + '</p>')\n"
        )
        assert achados == []


class TestRespostaDeView:
    def test_retorno_de_html_montado_em_view_e_reportado(self):
        achados = detectar_em_rota(
            "    nome = request.args['nome']\n    return '<h1>' + nome + '</h1>'"
        )
        assert len(achados) == 1

    def test_fstring_no_retorno_e_reportada(self):
        achados = detectar_em_rota(
            "    nome = request.args['nome']\n    return f'<h1>{nome}</h1>'"
        )
        assert len(achados) == 1

    @pytest.mark.parametrize(
        "construtor", ["make_response", "HttpResponse", "Response"]
    )
    def test_construtores_de_resposta_sao_sinks(self, construtor):
        achados = detectar_em_rota(
            "    nome = request.args['nome']\n"
            f"    return {construtor}('<p>' + nome + '</p>')"
        )
        assert len(achados) == 1, construtor

    def test_retorno_contaminado_fora_de_rota_nao_e_reportado(self):
        achados = detectar(
            "def helper():\n"
            "    nome = request.args['nome']\n"
            "    return '<h1>' + nome + '</h1>'\n"
        )
        assert achados == []

    def test_sink_de_resposta_nao_gera_achado_duplicado(self):
        achados = detectar_em_rota(
            "    return make_response('<p>' + request.args['q'] + '</p>')"
        )
        assert len(achados) == 1


class TestAusenciaDeFalsoPositivo:
    def test_amostra_segura_nao_gera_achado(self):
        assert detectar_arquivo(AMOSTRA_SEGURA) == []

    @pytest.mark.parametrize(
        "retorno",
        [
            "jsonify(termo=request.args['q'])",
            "JsonResponse({'q': request.args['q']})",
            "redirect(request.args['destino'])",
            "send_file(request.args['arquivo'])",
        ],
    )
    def test_resposta_nao_html_nao_e_xss(self, retorno):
        assert detectar_em_rota(f"    return {retorno}") == [], retorno

    def test_render_template_com_contexto_e_seguro(self):
        achados = detectar_em_rota(
            "    return render_template('ola.html', nome=request.args['nome'])"
        )
        assert achados == []

    def test_html_estatico_nao_e_reportado(self):
        assert detectar_em_rota("    return '<h1>Bem-vindo</h1>'") == []

    def test_escape_no_retorno_remove_o_achado(self):
        achados = detectar_em_rota(
            "    return '<p>' + escape(request.form['bio']) + '</p>'"
        )
        assert achados == []

    def test_cast_para_int_tambem_neutraliza_xss(self):
        achados = detectar_em_rota(
            "    total = int(request.args['n'])\n    return f'<p>{total}</p>'"
        )
        assert achados == []

    def test_amostra_de_sqli_nao_gera_ruido_de_xss(self):
        # Cruzamento entre detectores: nenhum dos dois deve inventar achado
        # no territorio do outro.
        assert detectar_arquivo(SQLI_VULNERAVEL) == []


class TestConfianca:
    def test_cadeia_direta_tem_confianca_alta(self):
        achados = detectar_em_rota(
            "    return '<h1>' + request.args['nome'] + '</h1>'"
        )
        assert achados[0].confianca == "alta"

    def test_cadeia_por_funcao_desconhecida_tem_confianca_media(self):
        achados = detectar_em_rota(
            "    nome = formatar(request.args['nome'])\n"
            "    return '<h1>' + nome + '</h1>'"
        )
        assert achados[0].confianca == "media"


class TestRenderizacaoComAutoEscape:
    @pytest.mark.parametrize(
        "retorno",
        [
            "render_template('ola.html', nome=request.args['nome'])",
            "render(request, 'ola.html', {'nome': request.GET['nome']})",
            "TemplateResponse(request, 'ola.html', {'q': request.args['q']})",
        ],
    )
    def test_template_com_auto_escape_nao_e_reportado(self, retorno):
        assert detectar_em_rota(f"    return {retorno}") == [], retorno

    def test_render_template_string_continua_sendo_sink(self):
        # A diferenca entre os dois: aqui o TEMPLATE e montado com dado
        # do usuario, entao o auto-escape nao protege.
        achados = detectar_em_rota(
            "    return render_template_string('<p>' + request.args['q'] + '</p>')"
        )
        assert len(achados) == 1
