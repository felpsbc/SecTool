"""Fase 16: credenciais em arquivos de configuracao nao-Python (CWE-798)."""

from pathlib import Path

import pytest

from conftest import DIRETORIO_AMOSTRAS, linhas_esperadas
from owaspscan.analisador import FalhaDeLeitura
from owaspscan.configuracao import (
    descobrir_configuracoes,
    formato_de,
    ler_configuracao,
    ler_json,
    ler_linhas_chave_valor,
    ler_yaml,
)
from owaspscan.detectores.credenciais import DetectorCredenciaisEmConfiguracao
from owaspscan.varredura import executar

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "config"
SEGURO = DIRETORIO_AMOSTRAS / "seguro" / "config"


def detectar_em(caminho: Path):
    lido = ler_configuracao(caminho, caminho.parent)
    assert not isinstance(lido, FalhaDeLeitura), lido
    return DetectorCredenciaisEmConfiguracao().detectar(lido)


def pares(entradas):
    return [(e.chave, e.valor) for e in entradas]


class TestDescoberta:
    @pytest.mark.parametrize(
        "nome,formato",
        [
            (".env", "env"),
            (".env.production", "env"),
            ("producao.env", "env"),
            ("docker-compose.yml", "yaml"),
            ("app.yaml", "yaml"),
            ("settings.json", "json"),
            ("setup.cfg", "ini"),
            ("app.properties", "properties"),
            ("pyproject.toml", "toml"),
        ],
    )
    def test_formatos(self, nome, formato):
        assert formato_de(Path(nome)) == formato

    @pytest.mark.parametrize("nome", ["app.py", "package-lock.json", "README.md"])
    def test_fora_do_escopo(self, nome):
        assert formato_de(Path(nome)) is None

    def test_ignora_diretorios_de_dependencia(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "x.json").write_text("{}")
        (tmp_path / "app.json").write_text("{}")
        assert [p.name for p in descobrir_configuracoes(tmp_path)] == ["app.json"]


class TestParsers:
    def test_env(self):
        texto = 'export A="x y"\nB=valor # comentario\n# C=z\nD=\'q\'\n'
        assert pares(ler_linhas_chave_valor(texto, "env")) == [
            ("A", "x y"), ("B", "valor"), ("D", "q")
        ]

    def test_toml_so_le_strings(self):
        texto = '[t]\nsenha = "abc"\nporta = 5432\nativo = true\n'
        assert pares(ler_linhas_chave_valor(texto, "toml")) == [("senha", "abc")]

    def test_properties_aceita_dois_pontos(self):
        assert pares(ler_linhas_chave_valor("a.b: c\n! x=y\n", "properties")) == [("a.b", "c")]

    def test_yaml(self):
        texto = (
            "servico:\n  senha: 'abc'\n  url: http://x\n  bloco: |\n"
            "  lista:\n    - SENHA=xyz\n    - nome: item\n"
        )
        assert pares(ler_yaml(texto)) == [
            ("senha", "abc"), ("url", "http://x"), ("SENHA", "xyz"), ("nome", "item")
        ]

    def test_json_com_linha(self):
        texto = '{\n  "db": {\n    "password": "abc123"\n  }\n}\n'
        [entrada] = ler_json(texto)
        assert (entrada.chave, entrada.valor, entrada.linha) == ("password", "abc123", 3)

    def test_json_invalido_vira_falha_registrada(self, tmp_path):
        arquivo = tmp_path / "quebrado.json"
        arquivo.write_text("{ nao e json")
        falha = ler_configuracao(arquivo, tmp_path)
        assert isinstance(falha, FalhaDeLeitura)
        assert falha.motivo == "sintaxe"


class TestAmostras:
    @pytest.mark.parametrize(
        "nome", ["producao.env", "docker-compose.yml", "application.properties", "servicos.ini", ".env.example"]
    )
    def test_vulneravel_bate_com_o_gabarito(self, nome):
        caminho = VULNERAVEL / nome
        assert [a.linha for a in detectar_em(caminho)] == linhas_esperadas(caminho, "CWE-798")

    @pytest.mark.parametrize("caminho", sorted(SEGURO.iterdir()), ids=lambda p: p.name)
    def test_seguro_nao_tem_achado(self, caminho):
        assert detectar_em(caminho) == []

    def test_arquivo_modelo_tem_severidade_baixa(self):
        [achado] = detectar_em(VULNERAVEL / ".env.example")
        assert (achado.severidade, achado.confianca) == ("baixa", "media")

    def test_segredo_nunca_aparece_no_relatorio(self):
        for achado in detectar_em(VULNERAVEL / "producao.env"):
            for segredo in ("postgres123", "Sup3rS3nh4", "wJalrXUtnFEMIK7MDENG"):
                assert segredo not in achado.trecho

    def test_json_vulneravel(self, tmp_path):
        # JSON nao admite comentario de gabarito: verificado aqui, fora do corpus.
        arquivo = tmp_path / "config.json"
        arquivo.write_text('{"db": {"password": "s3nh4-json"}, "api_key": "<sua-chave>"}')
        assert [a.linha for a in detectar_em(arquivo)] == [1]


class TestVarredura:
    def test_conta_arquivos_de_configuracao(self):
        varredura = executar(VULNERAVEL)
        assert varredura.arquivos_de_configuracao == len(descobrir_configuracoes(VULNERAVEL))
        assert varredura.arquivos_analisados == 0
        assert {a.cwe for a in varredura.achados} == {"CWE-798"}

    def test_arquivo_de_configuracao_como_raiz(self):
        varredura = executar(VULNERAVEL / "producao.env")
        assert varredura.arquivos_de_configuracao == 1
        assert len(varredura.achados) == 4

    def test_pode_desligar_configuracao(self):
        assert executar(VULNERAVEL, incluir_configuracao=False).achados == ()
