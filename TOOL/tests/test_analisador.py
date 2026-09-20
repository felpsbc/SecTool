"""Fase 1: camada AST — descoberta, parse resiliente e localizacao de nos."""

import ast
from pathlib import Path

import pytest

from owaspscan.analisador import (
    ArquivoAnalisado,
    FalhaDeLeitura,
    analisar_arquivo,
    analisar_diretorio,
    caminho_relativo,
    descobrir_arquivos,
    normalizar_trecho,
)

RAIZ_AMOSTRAS = Path(__file__).parent / "amostras" / "analisador"
EXEMPLO = RAIZ_AMOSTRAS / "modulo_exemplo.py"
QUEBRADO = RAIZ_AMOSTRAS / "quebrado.py"

# Linhas do fixture congelado tests/amostras/analisador/modulo_exemplo.py
LINHA_EXECUTE_SIMPLES = 7
LINHA_EXECUTE_MULTILINHA = 12


@pytest.fixture
def exemplo() -> ArquivoAnalisado:
    resultado = analisar_arquivo(EXEMPLO, RAIZ_AMOSTRAS)
    assert isinstance(resultado, ArquivoAnalisado)
    return resultado


def chamadas_execute(analisado: ArquivoAnalisado) -> list[ast.Call]:
    return [
        no
        for no in ast.walk(analisado.arvore)
        if isinstance(no, ast.Call)
        and isinstance(no.func, ast.Attribute)
        and no.func.attr == "execute"
    ]


class TestParse:
    def test_arquivo_valido_produz_arvore(self, exemplo):
        assert isinstance(exemplo.arvore, ast.Module)
        assert exemplo.fonte.startswith('"""Fixture congelado')

    def test_caminho_e_relativo_a_raiz(self):
        resultado = analisar_arquivo(EXEMPLO, RAIZ_AMOSTRAS.parent)
        assert resultado.arquivo == "analisador/modulo_exemplo.py"

    def test_caminho_fora_da_raiz_cai_para_o_nome(self, tmp_path):
        assert caminho_relativo(EXEMPLO, tmp_path) == "modulo_exemplo.py"


class TestLocalizacao:
    def test_linha_do_no_e_exata(self, exemplo):
        primeira, segunda = chamadas_execute(exemplo)
        assert exemplo.linha_de(primeira) == LINHA_EXECUTE_SIMPLES
        assert exemplo.linha_de(segunda) == LINHA_EXECUTE_MULTILINHA

    def test_trecho_reproduz_o_codigo_fonte(self, exemplo):
        primeira, _ = chamadas_execute(exemplo)
        assert exemplo.trecho_de(primeira) == (
            'cursor.execute("SELECT * FROM usuarios WHERE id = " + id_usuario)'
        )

    def test_trecho_multilinha_vira_uma_linha(self, exemplo):
        _, segunda = chamadas_execute(exemplo)
        trecho = exemplo.trecho_de(segunda)
        assert "\n" not in trecho
        assert trecho == (
            'cursor.execute( "SELECT * FROM usuarios WHERE id = " + id_usuario )'
        )

    def test_trecho_de_no_sem_posicao_nao_quebra(self, exemplo):
        assert exemplo.trecho_de(ast.Load()) == ""


class TestNormalizacaoDeTrecho:
    def test_colapsa_espacos_e_quebras(self):
        assert normalizar_trecho("a  =\n\t 1") == "a = 1"

    def test_trunca_com_reticencias(self):
        assert normalizar_trecho("x" * 200, limite=20) == "x" * 17 + "..."

    def test_nao_trunca_no_limite(self):
        assert normalizar_trecho("x" * 20, limite=20) == "x" * 20


class TestResilienciaAErros:
    def test_erro_de_sintaxe_vira_falha_registrada(self):
        resultado = analisar_arquivo(QUEBRADO, RAIZ_AMOSTRAS)
        assert isinstance(resultado, FalhaDeLeitura)
        assert resultado.motivo == "sintaxe"
        assert resultado.arquivo == "quebrado.py"
        assert resultado.linha == 1

    def test_arquivo_inexistente_vira_falha_de_io(self, tmp_path):
        resultado = analisar_arquivo(tmp_path / "nao_existe.py", tmp_path)
        assert isinstance(resultado, FalhaDeLeitura)
        assert resultado.motivo == "io"

    def test_codificacao_invalida_vira_falha(self, tmp_path):
        arquivo = tmp_path / "latin.py"
        arquivo.write_bytes(b'x = "acentua\xe7\xe3o"\n')
        resultado = analisar_arquivo(arquivo, tmp_path)
        assert isinstance(resultado, FalhaDeLeitura)
        assert resultado.motivo == "codificacao"


class TestDescoberta:
    def test_encontra_py_recursivamente_em_ordem_estavel(self, tmp_path):
        (tmp_path / "pacote" / "sub").mkdir(parents=True)
        (tmp_path / "b.py").write_text("")
        (tmp_path / "a.py").write_text("")
        (tmp_path / "pacote" / "sub" / "c.py").write_text("")
        (tmp_path / "leiame.txt").write_text("nao e python")

        encontrados = [caminho_relativo(p, tmp_path) for p in descobrir_arquivos(tmp_path)]
        assert encontrados == ["a.py", "b.py", "pacote/sub/c.py"]

    def test_ignora_diretorios_de_build_e_ambiente(self, tmp_path):
        for pasta in (".venv", "__pycache__", "node_modules"):
            (tmp_path / pasta).mkdir()
            (tmp_path / pasta / "lixo.py").write_text("")
        (tmp_path / "app.py").write_text("")

        encontrados = [caminho_relativo(p, tmp_path) for p in descobrir_arquivos(tmp_path)]
        assert encontrados == ["app.py"]

    def test_aceita_arquivo_unico_como_raiz(self):
        assert descobrir_arquivos(EXEMPLO) == [EXEMPLO]


class TestVarreduraDeDiretorio:
    def test_separa_sucessos_de_falhas_e_continua(self):
        analisados, falhas = analisar_diretorio(RAIZ_AMOSTRAS)
        assert [a.arquivo for a in analisados] == ["modulo_exemplo.py"]
        assert [f.arquivo for f in falhas] == ["quebrado.py"]

    def test_diretorio_vazio_nao_quebra(self, tmp_path):
        assert analisar_diretorio(tmp_path) == ([], [])
