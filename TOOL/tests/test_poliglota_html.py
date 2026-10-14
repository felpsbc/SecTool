"""Fase 25: HTML (JavaScript embutido e formularios sem token CSRF)."""

import pytest

pytest.importorskip("tree_sitter_html")

from owaspscan.poliglota.fonte import analisar_texto_poliglota
from owaspscan.poliglota.registro import detectar_poliglota


def pares(html: str):
    arquivo = analisar_texto_poliglota(html, "html", "p.html")
    return sorted((a.linha, a.cwe, a.confianca) for a in detectar_poliglota(arquivo))


class TestJavaScriptEmbutido:
    def test_linha_do_script_e_a_linha_da_pagina(self):
        html = "<p>a</p>\n<p>b</p>\n<script>\n\ndocument.write(location.hash);\n</script>"
        assert pares(html) == [(5, "CWE-79", "alta")]

    def test_atributo_de_evento(self):
        html = '<p>\n<a onclick="location.href = location.hash">x</a>'
        assert pares(html) == [(2, "CWE-601", "alta")]

    def test_script_externo_e_nao_javascript_sao_ignorados(self):
        html = (
            '<script src="a.js"></script>\n'
            '<script type="application/json">{"password": "x1234567"}</script>'
        )
        assert pares(html) == []

    def test_script_module_e_analisado(self):
        assert pares('<script type="module">const API_KEY = "k-1234567";</script>') == [
            (1, "CWE-798", "alta")
        ]


class TestCsrf:
    def test_form_post_sem_token_e_candidato(self):
        assert pares('<form method="POST"><input name="x"></form>') == [(1, "CWE-352", "baixa")]

    @pytest.mark.parametrize(
        "conteudo",
        [
            '<input type="hidden" name="_token" value="1">',
            '<input type=hidden name=csrfmiddlewaretoken>',
            "{% csrf_token %}",
            "@csrf",
        ],
    )
    def test_form_com_token(self, conteudo):
        assert pares(f'<form method="post">{conteudo}<input name="x"></form>') == []

    def test_form_get_nao_precisa_de_token(self):
        assert pares('<form action="/busca"><input name="q"></form>') == []
