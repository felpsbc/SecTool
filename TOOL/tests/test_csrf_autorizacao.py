"""Fase 13: CSRF desligado (CWE-352) e rota sem autorizacao (CWE-862)."""

import pytest

from conftest import (
    DIRETORIO_AMOSTRAS,
    linhas_esperadas,
    rodar_detector,
    rodar_detector_em_arquivo,
)
from owaspscan.detectores.autorizacao import PREFIXO_CANDIDATO, DetectorAutorizacao
from owaspscan.detectores.csrf import DetectorCsrf

VULNERAVEIS_CSRF = ["flask_csrf.py", "django_csrf.py"]
SEGUROS_CSRF = ["flask_csrf.py", "django_csrf.py", "flask_api_token.py"]
SEGUROS_AUTORIZACAO = ["flask_autorizacao.py", "flask_blueprint_hook.py"]


class TestCsrfAmostras:
    @pytest.mark.parametrize("nome", VULNERAVEIS_CSRF)
    def test_vulneravel_bate_com_o_gabarito(self, nome):
        caminho = DIRETORIO_AMOSTRAS / "vulneravel" / nome
        achados = rodar_detector_em_arquivo(DetectorCsrf(), caminho)
        assert sorted(a.linha for a in achados) == linhas_esperadas(caminho, "CWE-352")

    @pytest.mark.parametrize("nome", SEGUROS_CSRF)
    def test_seguro_nao_tem_achado(self, nome):
        caminho = DIRETORIO_AMOSTRAS / "seguro" / nome
        assert rodar_detector_em_arquivo(DetectorCsrf(), caminho) == []


class TestCsrfRegras:
    def test_csrf_exempt_e_alta_confianca(self):
        achados = rodar_detector(DetectorCsrf(), "@csrf_exempt\ndef v(request): pass\n")
        assert [(a.linha, a.confianca) for a in achados] == [(1, "alta")]

    def test_exempt_do_flask_wtf(self):
        fonte = "@csrf.exempt\n@app.route('/x', methods=['POST'])\ndef v(): pass\n"
        assert len(rodar_detector(DetectorCsrf(), fonte)) == 1

    def test_exempt_sem_csrf_no_nome_nao_acusa(self):
        assert rodar_detector(DetectorCsrf(), "@limiter.exempt\ndef v(): pass\n") == []

    def test_app_sem_protecao_e_candidato(self):
        fonte = (
            "from flask import Flask\napp = Flask(__name__)\n"
            "@app.post('/x')\ndef v(): pass\n"
        )
        achados = rodar_detector(DetectorCsrf(), fonte)
        assert [a.confianca for a in achados] == ["baixa"]
        assert achados[0].descricao.startswith("Candidato a CSRF")

    def test_app_so_com_get_nao_e_candidato(self):
        fonte = "from flask import Flask\napp = Flask(__name__)\n@app.get('/x')\ndef v(): pass\n"
        assert rodar_detector(DetectorCsrf(), fonte) == []

    def test_middleware_dinamico_nao_e_julgado(self):
        assert rodar_detector(DetectorCsrf(), "MIDDLEWARE = BASE + ['django.x']\n") == []


class TestAutorizacaoAmostras:
    def test_vulneravel_bate_com_o_gabarito(self):
        caminho = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_autorizacao.py"
        achados = rodar_detector_em_arquivo(DetectorAutorizacao(), caminho)
        assert sorted(a.linha for a in achados) == linhas_esperadas(caminho, "CWE-862")

    @pytest.mark.parametrize("nome", SEGUROS_AUTORIZACAO)
    def test_seguro_nao_tem_candidato(self, nome):
        caminho = DIRETORIO_AMOSTRAS / "seguro" / nome
        assert rodar_detector_em_arquivo(DetectorAutorizacao(), caminho) == []

    def test_sempre_candidato_honesto(self):
        caminho = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_autorizacao.py"
        for achado in rodar_detector_em_arquivo(DetectorAutorizacao(), caminho):
            assert achado.confianca == "baixa"
            assert achado.descricao.startswith(PREFIXO_CANDIDATO)
            assert "NAO afirma vulnerabilidade" in achado.descricao
            assert achado.owasp == "A01:2021 Broken Access Control"


class TestAutorizacaoRegras:
    def detectar(self, fonte):
        return rodar_detector(DetectorAutorizacao(), fonte)

    def test_admin_com_login_required_continua_candidato(self):
        fonte = "@app.route('/admin')\n@login_required\ndef painel(): pass\n"
        achados = self.detectar(fonte)
        assert len(achados) == 1
        assert "apenas autenticacao" in achados[0].descricao

    def test_post_com_login_required_nao_e_candidato(self):
        fonte = "@app.post('/x')\n@login_required\ndef v(): pass\n"
        assert self.detectar(fonte) == []

    def test_rota_publica_por_natureza_e_ignorada(self):
        assert self.detectar("@app.post('/cadastro')\ndef novo(): pass\n") == []

    def test_checagem_de_papel_no_corpo_suprime_admin(self):
        fonte = (
            "@app.route('/admin')\ndef painel():\n"
            "    if not current_user.has_role('admin'):\n        abort(403)\n"
        )
        assert self.detectar(fonte) == []

    def test_so_is_authenticated_nao_basta_para_admin(self):
        fonte = (
            "@app.route('/admin')\ndef painel():\n"
            "    if not current_user.is_authenticated:\n        abort(401)\n"
        )
        assert len(self.detectar(fonte)) == 1

    def test_get_comum_nao_e_candidato(self):
        assert self.detectar("@app.get('/produtos')\ndef v(): pass\n") == []
