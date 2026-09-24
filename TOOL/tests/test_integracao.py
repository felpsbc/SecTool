"""Fase 8: varredura ponta-a-ponta e interface de linha de comando."""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from conftest import DIRETORIO_AMOSTRAS
from owaspscan.metricas import carregar_gabarito
from owaspscan.cli import CODIGO_ACHADO_ALTO, CODIGO_ERRO_DE_USO, CODIGO_OK, main
from owaspscan.varredura import executar

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel"
SEGURO = DIRETORIO_AMOSTRAS / "seguro"
RAIZ_PROJETO = Path(__file__).resolve().parent.parent


class TestVarreduraCompleta:
    def test_encontra_todas_as_cwes_do_gabarito_na_pasta_vulneravel(self):
        varredura = executar(VULNERAVEL, momento=datetime(2026, 9, 16))
        esperadas = {i.cwe for i in carregar_gabarito(VULNERAVEL) if not i.limitacao}
        assert {a.cwe for a in varredura.achados} == esperadas

    def test_conta_arquivos_analisados(self):
        varredura = executar(VULNERAVEL)
        assert varredura.arquivos_analisados == len(list(VULNERAVEL.glob("*.py")))
        assert varredura.falhas == ()

    def test_pasta_segura_nao_tem_achado_de_alta_severidade(self):
        varredura = executar(SEGURO)
        assert not varredura.tem_severidade_alta

    def test_pasta_segura_so_confirma_o_que_o_gabarito_marca(self):
        # As amostras sao seguras para a CWE que nomeiam, nao para todas:
        # query parametrizada resolve CWE-89, nao CWE-639. Todo achado
        # confirmado ali precisa estar rotulado no gabarito.
        varredura = executar(SEGURO)
        gabarito = {i.chave for i in carregar_gabarito(SEGURO)}
        assert {(a.arquivo, a.linha, a.cwe) for a in varredura.confirmados} <= gabarito

    def test_pasta_segura_nao_tem_achado_da_cwe_que_cada_arquivo_nomeia(self):
        nomeadas = {
            "flask_sqli.py": "CWE-89",
            "flask_xss.py": "CWE-79",
            "flask_idor.py": "CWE-639",
            "flask_xxe.py": "CWE-611",
            "flask_path_traversal.py": "CWE-22",
            "flask_open_redirect.py": "CWE-601",
            "flask_csrf.py": "CWE-352",
            "django_csrf.py": "CWE-352",
            "flask_api_token.py": "CWE-352",
            "flask_autorizacao.py": "CWE-862",
            "flask_blueprint_hook.py": "CWE-862",
        }
        for achado in executar(SEGURO).achados:
            assert nomeadas.get(achado.arquivo) != achado.cwe, achado

    def test_achados_saem_ordenados_por_arquivo_e_linha(self):
        achados = executar(VULNERAVEL).achados
        chaves = [(a.arquivo, a.linha, a.cwe) for a in achados]
        assert chaves == sorted(chaves)

    def test_arquivo_unico_como_raiz(self):
        amostra = VULNERAVEL / "flask_sqli.py"
        varredura = executar(amostra)
        assert varredura.arquivos_analisados == 1
        esperadas = {i.cwe for i in carregar_gabarito(amostra) if not i.limitacao}
        assert {"CWE-89", "CWE-639"} <= esperadas
        assert {a.cwe for a in varredura.achados} == esperadas

    def test_arquivo_quebrado_nao_derruba_a_varredura(self, tmp_path):
        (tmp_path / "ok.py").write_text(
            "def view(c):\n    c.execute('S ' + request.args['id'])\n"
        )
        (tmp_path / "quebrado.py").write_text("def view(:\n")
        varredura = executar(tmp_path)
        assert varredura.arquivos_analisados == 1
        assert len(varredura.falhas) == 1
        assert varredura.falhas[0].motivo == "sintaxe"
        assert len(varredura.achados) == 1

    def test_diretorio_vazio_produz_varredura_vazia(self, tmp_path):
        varredura = executar(tmp_path)
        assert varredura.achados == ()
        assert varredura.arquivos_analisados == 0


class TestCodigosDeSaida:
    def test_achado_de_alta_severidade_retorna_1(self, capsys):
        assert main([str(VULNERAVEL)]) == CODIGO_ACHADO_ALTO

    def test_sem_alta_severidade_retorna_0(self, capsys):
        assert main([str(SEGURO)]) == CODIGO_OK

    def test_candidato_heuristico_nao_quebra_o_build(self, capsys):
        # A pasta segura tem candidatos a IDOR; o codigo de saida segue 0.
        assert main([str(SEGURO)]) == CODIGO_OK
        saida = capsys.readouterr().out
        assert "CWE-639" in saida

    def test_caminho_inexistente_retorna_2(self, capsys):
        assert main(["nao/existe"]) == CODIGO_ERRO_DE_USO
        assert "caminho nao encontrado" in capsys.readouterr().err

    def test_projeto_sem_achados_retorna_0(self, tmp_path, capsys):
        (tmp_path / "limpo.py").write_text("def somar(a, b):\n    return a + b\n")
        assert main([str(tmp_path)]) == CODIGO_OK


class TestSaidaDaCli:
    def test_texto_vai_para_stdout_por_padrao(self, capsys):
        main([str(VULNERAVEL)])
        capturado = capsys.readouterr()
        assert "resumo executivo" in capturado.out
        assert capturado.err == ""

    def test_json_vai_para_stdout_e_texto_para_stderr(self, capsys):
        main([str(VULNERAVEL), "--json"])
        capturado = capsys.readouterr()
        dados = json.loads(capturado.out)
        assert dados["ferramenta"] == "owasp-scan"
        assert "resumo executivo" in capturado.err

    def test_json_traz_achados_e_metadados(self, capsys):
        main([str(VULNERAVEL), "--json"])
        dados = json.loads(capsys.readouterr().out)
        assert dados["varredura"]["arquivos_analisados"] == len(
            list(VULNERAVEL.glob("*.py"))
        )
        assert dados["resumo"]["total"] == len(dados["achados"])
        assert dados["resumo"]["candidatos_heuristicos"] > 0

    def test_relatorio_separa_achados_de_candidatos(self, capsys):
        main([str(VULNERAVEL)])
        saida = capsys.readouterr().out
        assert "ACHADOS RASTREADOS POR TAINT" in saida
        assert "CANDIDATOS HEURISTICOS" in saida
        assert "NAO afirmam vulnerabilidade" in saida


class TestExecucaoComoModulo:
    def test_python_m_owaspscan_funciona(self):
        processo = subprocess.run(
            [sys.executable, "-m", "owaspscan", str(VULNERAVEL)],
            capture_output=True,
            text=True,
            cwd=RAIZ_PROJETO,
        )
        assert processo.returncode == CODIGO_ACHADO_ALTO
        assert "OWASP-Scan" in processo.stdout

    def test_json_do_processo_e_parseavel(self):
        processo = subprocess.run(
            [sys.executable, "-m", "owaspscan", str(SEGURO), "--json"],
            capture_output=True,
            text=True,
            cwd=RAIZ_PROJETO,
        )
        assert processo.returncode == CODIGO_OK
        dados = json.loads(processo.stdout)
        assert dados["resumo"]["total"] == len(dados["achados"])
