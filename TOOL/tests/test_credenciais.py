"""Fase 15: credenciais fixas no codigo Python (CWE-798)."""

import pytest

from conftest import (
    DIRETORIO_AMOSTRAS,
    linhas_esperadas,
    rodar_detector,
    rodar_detector_em_arquivo,
)
from owaspscan.detectores.credenciais import DetectorCredenciais
from owaspscan.motor.credenciais import (
    e_placeholder,
    mascarar,
    nomeia_credencial,
    url_com_senha,
)

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "credenciais_codigo.py"
SEGURO = DIRETORIO_AMOSTRAS / "seguro" / "credenciais_codigo.py"


def detectar(fonte: str):
    return rodar_detector(DetectorCredenciais(), fonte)


class TestAmostras:
    def test_vulneravel_bate_com_o_gabarito(self):
        achados = rodar_detector_em_arquivo(DetectorCredenciais(), VULNERAVEL)
        assert [a.linha for a in achados] == linhas_esperadas(VULNERAVEL, "CWE-798")

    def test_seguro_nao_tem_achado(self):
        assert rodar_detector_em_arquivo(DetectorCredenciais(), SEGURO) == []

    def test_classificacao(self):
        for achado in rodar_detector_em_arquivo(DetectorCredenciais(), VULNERAVEL):
            assert achado.owasp == "A07:2021 Identification and Authentication Failures"
            assert achado.vulnerabilidade == "Hard-coded Credentials"
            assert achado.severidade == "alta"

    def test_relatorio_nunca_carrega_o_segredo(self):
        segredos = ["dev-secret-nao-usar", "Sup3rS3nh4", "admin123", "M4st3rK3y!", "p4rc3ir0"]
        for achado in rodar_detector_em_arquivo(DetectorCredenciais(), VULNERAVEL):
            for segredo in segredos:
                assert segredo not in achado.trecho
                assert segredo not in achado.descricao


class TestNome:
    @pytest.mark.parametrize(
        "nome",
        ["password", "DB_PASSWORD", "dbPassword", "senha", "SECRET_KEY", "api_key",
         "apiKey", "chave_api", "client_secret", "auth_token", "private_key",
         "spring.datasource.password"],
    )
    def test_nomes_de_credencial(self, nome):
        assert nomeia_credencial(nome)

    @pytest.mark.parametrize(
        "nome",
        ["PASSWORD_MIN_LENGTH", "token_url", "token_type", "password_field", "is_secret",
         "senha_minima", "username", "api_version", "key", "tokenizer", "bypass",
         "flask_api_token.py"],
    )
    def test_metadados_e_outros_nomes_nao_sao_credencial(self, nome):
        assert not nomeia_credencial(nome)


class TestValor:
    @pytest.mark.parametrize(
        "valor", ["", "ab", "****", "${DB_PASS}", "{{ senha }}", "<sua-chave>", "your_api_key", "None"]
    )
    def test_placeholders(self, valor):
        assert e_placeholder(valor)

    @pytest.mark.parametrize("valor", ["admin", "123456", "changeme", "password"])
    def test_senhas_fracas_nao_sao_placeholder(self, valor):
        # "changeme" e "password" sao credenciais reais quando vao para producao.
        assert not e_placeholder(valor)

    def test_url_com_senha(self):
        assert url_com_senha("redis://:s3nh4@cache:6379/0") == "redis"
        assert url_com_senha("postgres://u:${SENHA}@db/x") is None
        assert url_com_senha("https://site.com/a@b") is None

    def test_mascarar_preserva_contexto(self):
        assert mascarar('SENHA = "abcdefgh"', "abcdefgh") == 'SENHA = "ab***"'
        assert mascarar('S = "abc"', "abc") == 'S = "***"'


class TestFormas:
    @pytest.mark.parametrize(
        "fonte",
        [
            "app.secret_key = 'segredo-fixo'\n",
            "app.config['SECRET_KEY'] = 'segredo-fixo'\n",
            "usuario, senha = 'admin', 'admin123'\n",
            "senha: str = 'admin123'\n",
            "def f(*, api_key='abc123xyz'): pass\n",
            "HTTPBasicAuth('u', 'segredo1')\n",
            "if request.form['senha'] == 'master':\n    pass\n",
            "os.environ.get('API_TOKEN', 'tok-fixo-123')\n",
            "config('SECRET_KEY', default='dev-key')\n",
        ],
    )
    def test_formas_reconhecidas(self, fonte):
        assert len(detectar(fonte)) == 1

    def test_get_de_dicionario_nao_e_ambiente(self):
        assert detectar("cfg.get('SECRET_KEY', 'x-padrao')\n") == []

    def test_fallback_de_ambiente_tem_confianca_media(self):
        assert [a.confianca for a in detectar("os.getenv('SECRET_KEY', 'dev')\n")] == ["media"]

    def test_url_em_docstring_nao_acusa(self):
        assert detectar('"""Use postgres://app:senha123@db/x."""\n') == []

    def test_um_achado_por_literal(self):
        assert len(detectar("PASSWORD = {'password': 'abc123'}['password']\n")) == 1
