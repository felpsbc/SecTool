"""Fase 10: consultas estruturais compartilhadas pelos novos detectores."""

import ast

import pytest

from owaspscan.motor.estrutura import (
    atribuicoes_de_configuracao,
    caminhos_da_rota,
    funcoes_de_rota,
    mapa_de_importacoes,
    metodos_http,
    nome_qualificado,
    tokens_de_nome,
)


def _funcao(fonte: str) -> ast.FunctionDef:
    return next(n for n in ast.walk(ast.parse(fonte)) if isinstance(n, ast.FunctionDef))


class TestImportacoes:
    def test_from_import_resolve_alias(self):
        mapa = mapa_de_importacoes(ast.parse("from lxml import etree"))
        chamada = ast.parse("etree.fromstring(x)").body[0].value
        assert nome_qualificado(chamada.func, mapa) == "lxml.etree.fromstring"

    def test_import_com_as(self):
        mapa = mapa_de_importacoes(ast.parse("import xml.etree.ElementTree as ET"))
        chamada = ast.parse("ET.fromstring(x)").body[0].value
        assert nome_qualificado(chamada.func, mapa) == "xml.etree.ElementTree.fromstring"

    def test_import_pontilhado_sem_as_liga_a_raiz(self):
        mapa = mapa_de_importacoes(ast.parse("import lxml.etree"))
        chamada = ast.parse("lxml.etree.parse(x)").body[0].value
        assert nome_qualificado(chamada.func, mapa) == "lxml.etree.parse"

    def test_nome_nao_importado_fica_como_esta(self):
        chamada = ast.parse("fromstring(x)").body[0].value
        assert nome_qualificado(chamada.func, {}) == "fromstring"


class TestConfiguracao:
    @pytest.mark.parametrize(
        "fonte",
        [
            "SESSION_COOKIE_SECURE = False",
            "app.config['SESSION_COOKIE_SECURE'] = False",
            "app.config.update(SESSION_COOKIE_SECURE=False)",
            "app.config.update({'SESSION_COOKIE_SECURE': False})",
            "app.config.from_mapping(SESSION_COOKIE_SECURE=False)",
            "class Config:\n    SESSION_COOKIE_SECURE = False",
        ],
    )
    def test_formas_reconhecidas(self, fonte):
        atribuicoes = list(atribuicoes_de_configuracao(ast.parse(fonte)))
        assert [a.chave for a in atribuicoes] == ["SESSION_COOKIE_SECURE"]
        assert atribuicoes[0].valor.value is False

    def test_variavel_minuscula_nao_e_configuracao(self):
        assert list(atribuicoes_de_configuracao(ast.parse("segredo = 'x'"))) == []

    def test_update_de_dicionario_comum_nao_e_configuracao(self):
        assert list(atribuicoes_de_configuracao(ast.parse("d.update(X=1)"))) == []


class TestRotas:
    def test_route_sem_methods_e_get(self):
        assert metodos_http(_funcao("@app.route('/a')\ndef v(): pass")) == {"GET"}

    def test_route_com_methods(self):
        fonte = "@app.route('/a', methods=['GET', 'post'])\ndef v(): pass"
        assert metodos_http(_funcao(fonte)) == {"GET", "POST"}

    def test_decorador_por_metodo(self):
        assert metodos_http(_funcao("@app.delete('/a')\ndef v(): pass")) == {"DELETE"}

    def test_methods_nao_literal_assume_pior_caso(self):
        fonte = "@app.route('/a', methods=M)\ndef v(): pass"
        assert "POST" in metodos_http(_funcao(fonte))

    def test_funcao_comum_nao_tem_metodo(self):
        assert metodos_http(_funcao("def v(): pass")) == frozenset()

    def test_caminho_da_rota(self):
        assert caminhos_da_rota(_funcao("@bp.route('/admin/x')\ndef v(): pass")) == [
            "/admin/x"
        ]

    def test_funcoes_de_rota(self):
        arvore = ast.parse("@app.get('/')\ndef a(): pass\ndef b(): pass")
        assert [f.name for f in funcoes_de_rota(arvore)] == ["a"]


class TestTokensDeNome:
    @pytest.mark.parametrize(
        "nome,esperado",
        [
            ("DB_PASSWORD", ["db", "password"]),
            ("dbPassword", ["db", "password"]),
            ("api-key", ["api", "key"]),
            ("senha", ["senha"]),
        ],
    )
    def test_quebra(self, nome, esperado):
        assert tokens_de_nome(nome) == esperado
