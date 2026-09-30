"""Fase 18: camada HTTP (POST /analisar) sobre executar() + para_dict()."""

import pytest

pytest.importorskip("fastapi", reason="extra [api] nao instalado")
pytest.importorskip("httpx", reason="TestClient do FastAPI exige httpx")

from fastapi.testclient import TestClient

from conftest import DIRETORIO_AMOSTRAS
from owaspscan.api import MAXIMO_DE_ARQUIVOS, TAMANHO_MAXIMO_POR_ARQUIVO, app, nome_seguro

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel"
SEGURO = DIRETORIO_AMOSTRAS / "seguro"

SQLI = """\
from flask import request
import sqlite3

def buscar():
    ident = request.args["id"]
    sqlite3.connect("x.db").execute("SELECT * FROM t WHERE id = " + ident)
"""


@pytest.fixture
def cliente():
    return TestClient(app)


def _cwes(corpo) -> set[str]:
    return {achado["cwe"] for achado in corpo["achados"]}


class TestCodigoColado:
    def test_detecta_sqli_em_codigo_colado(self, cliente):
        resposta = cliente.post("/analisar", data={"codigo": SQLI})
        assert resposta.status_code == 200
        corpo = resposta.json()
        assert "CWE-89" in _cwes(corpo)
        assert corpo["achados"][0]["arquivo"] == "codigo.py"

    def test_nome_do_codigo_colado_e_configuravel(self, cliente):
        resposta = cliente.post("/analisar", data={"codigo": SQLI, "nome": "views.py"})
        assert {a["arquivo"] for a in resposta.json()["achados"]} == {"views.py"}

    def test_resposta_segue_o_formato_de_para_dict(self, cliente):
        corpo = cliente.post("/analisar", data={"codigo": SQLI}).json()
        assert corpo["ferramenta"] == "owasp-scan"
        assert set(corpo) >= {"versao", "raiz", "momento", "varredura", "resumo", "achados"}
        assert corpo["varredura"]["arquivos_analisados"] == 1

    def test_nao_vaza_caminho_temporario_do_servidor(self, cliente):
        corpo = cliente.post("/analisar", data={"codigo": SQLI}).json()
        assert corpo["raiz"] == "envio"
        assert "owaspscan-" not in str(corpo)

    def test_erro_de_sintaxe_vira_falha_registrada_nao_erro_http(self, cliente):
        corpo = cliente.post("/analisar", data={"codigo": "def quebrado(:\n"}).json()
        assert corpo["varredura"]["arquivos_com_falha"] == 1
        assert corpo["varredura"]["falhas"][0]["motivo"] == "sintaxe"


class TestArquivosEnviados:
    def test_varios_arquivos_de_uma_vez(self, cliente):
        nomes = ["flask_sqli.py", "flask_xss.py"]
        arquivos = [("arquivos", (n, (VULNERAVEL / n).read_bytes())) for n in nomes]
        corpo = cliente.post("/analisar", files=arquivos).json()
        assert corpo["varredura"]["arquivos_analisados"] == 2
        assert {"CWE-89", "CWE-79"} <= _cwes(corpo)
        assert set(corpo["resumo"]["por_arquivo"]) <= set(nomes)

    def test_arquivo_de_configuracao(self, cliente):
        env = b'SECRET_KEY="uma-chave-de-producao-real-9f8e7d"\n'
        corpo = cliente.post("/analisar", files=[("arquivos", (".env", env))]).json()
        assert corpo["varredura"]["arquivos_de_configuracao"] == 1
        assert "CWE-798" in _cwes(corpo)

    def test_codigo_e_arquivos_no_mesmo_envio(self, cliente):
        arquivo = ("arquivos", ("outro.py", b"x = 1\n"))
        corpo = cliente.post("/analisar", data={"codigo": SQLI}, files=[arquivo]).json()
        assert corpo["varredura"]["arquivos_analisados"] == 2

    def test_amostra_segura_nao_gera_achado_alto(self, cliente):
        amostra = sorted(SEGURO.glob("*.py"))[0]
        arquivo = ("arquivos", (amostra.name, amostra.read_bytes()))
        corpo = cliente.post("/analisar", files=[arquivo]).json()
        assert corpo["resumo"]["por_severidade"].get("alta", 0) == 0


class TestEntradaHostil:
    @pytest.mark.parametrize(
        "enviado, gravado",
        [
            ("../../etc/app.py", "app.py"),
            ("/abs/views.py", "views.py"),
            ("C:\\projeto\\models.py", "models.py"),
            ("config/.env", ".env"),
        ],
    )
    def test_nome_de_arquivo_perde_diretorios(self, enviado, gravado):
        assert nome_seguro(enviado) == gravado

    def test_path_traversal_no_nome_e_neutralizado(self, cliente):
        arquivo = ("arquivos", ("../../fora.py", SQLI.encode()))
        corpo = cliente.post("/analisar", files=[arquivo]).json()
        assert {a["arquivo"] for a in corpo["achados"]} == {"fora.py"}

    @pytest.mark.parametrize("nome", ["..", "foto.png", "script.sh"])
    def test_rejeita_nome_invalido_ou_tipo_nao_suportado(self, cliente, nome):
        resposta = cliente.post("/analisar", files=[("arquivos", (nome, b"x"))])
        assert resposta.status_code == 400

    def test_rejeita_envio_vazio(self, cliente):
        assert cliente.post("/analisar", data={"codigo": "   "}).status_code == 400

    def test_rejeita_nomes_repetidos(self, cliente):
        arquivos = [("arquivos", ("a.py", b"x = 1\n")), ("arquivos", ("a.py", b"y = 2\n"))]
        assert cliente.post("/analisar", files=arquivos).status_code == 400

    def test_rejeita_arquivo_grande_demais(self, cliente):
        grande = b"#" * (TAMANHO_MAXIMO_POR_ARQUIVO + 1)
        resposta = cliente.post("/analisar", files=[("arquivos", ("grande.py", grande))])
        assert resposta.status_code == 413

    def test_rejeita_arquivos_demais(self, cliente):
        arquivos = [("arquivos", (f"m{i}.py", b"x = 1\n")) for i in range(MAXIMO_DE_ARQUIVOS + 1)]
        assert cliente.post("/analisar", files=arquivos).status_code == 413


def test_saude(cliente):
    assert cliente.get("/saude").json()["status"] == "ok"
