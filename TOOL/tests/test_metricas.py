"""Fase 9: avaliacao contra o corpus rotulado.

Este e o teste que produz os numeros do relatorio da IC. Ele tambem guarda
a honestidade da medicao: falso negativo declarado continua contando como
falso negativo.
"""

import pytest

from conftest import DIRETORIO_AMOSTRAS
from owaspscan.metricas import (
    AVISO_DE_ESCOPO,
    Metricas,
    avaliar,
    carregar_gabarito,
    formatar_tabela,
    main,
)
from owaspscan.varredura import executar


class TestLeituraDoGabarito:
    def test_le_marcador_simples(self, tmp_path):
        arquivo = tmp_path / "a.py"
        arquivo.write_text("x = 1\ncursor.execute(q)  # achado: CWE-89\n")
        itens = carregar_gabarito(arquivo)
        assert [(i.linha, i.cwe) for i in itens] == [(2, "CWE-89")]

    def test_le_marcador_com_varias_cwes(self, tmp_path):
        arquivo = tmp_path / "a.py"
        arquivo.write_text("cursor.execute(q)  # achado: CWE-89, CWE-639\n")
        assert {i.cwe for i in carregar_gabarito(arquivo)} == {"CWE-89", "CWE-639"}

    def test_ignora_cwe_fora_do_mapa(self, tmp_path):
        arquivo = tmp_path / "a.py"
        arquivo.write_text("f()  # achado: CWE-1234\n")
        assert carregar_gabarito(arquivo) == []

    def test_le_limitacao_com_motivo(self, tmp_path):
        arquivo = tmp_path / "a.py"
        arquivo.write_text("f()  # limitacao: CWE-89 fluxo interprocedural\n")
        item = carregar_gabarito(arquivo)[0]
        assert item.cwe == "CWE-89"
        assert item.limitacao == "fluxo interprocedural"

    def test_le_diretorio_inteiro_com_caminho_relativo(self):
        itens = carregar_gabarito(DIRETORIO_AMOSTRAS)
        arquivos = {item.arquivo for item in itens}
        assert "vulneravel/flask_sqli.py" in arquivos
        assert "seguro/flask_sqli.py" in arquivos


class TestCalculoDasMetricas:
    def test_taxas(self):
        m = Metricas(vp=8, fp=2, fn=2)
        assert m.precisao == 0.8
        assert m.recall == 0.8
        assert m.f1 == pytest.approx(0.8)

    def test_sem_achados_nao_divide_por_zero(self):
        m = Metricas()
        assert (m.precisao, m.recall, m.f1) == (0.0, 0.0, 0.0)

    def test_precisao_perfeita_com_recall_parcial(self):
        m = Metricas(vp=5, fp=0, fn=5)
        assert m.precisao == 1.0
        assert m.recall == 0.5
        assert m.f1 == pytest.approx(2 / 3)


@pytest.fixture(scope="module")
def metricas():
    return avaliar(DIRETORIO_AMOSTRAS)


class TestAvaliacaoDoCorpus:
    def test_cobre_as_cwes_do_gabarito_e_o_total(self, metricas):
        cwes = {item.cwe for item in carregar_gabarito(DIRETORIO_AMOSTRAS)}
        assert set(metricas) == cwes | {"geral"}

    def test_nenhum_falso_positivo_no_corpus(self, metricas):
        assert metricas["geral"].fp == 0

    def test_o_unico_falso_negativo_e_a_limitacao_declarada(self, metricas):
        geral = metricas["geral"]
        assert geral.fn == 1
        assert geral.fn_conhecidos == 1

    def test_limitacao_declarada_nao_vira_isencao(self, metricas):
        # O recall NAO desconta o falso negativo conhecido: declarar a falha
        # nao a transforma em acerto.
        assert metricas["CWE-89"].recall < 1.0

    def test_xss_tem_recall_total_no_corpus(self, metricas):
        assert metricas["CWE-79"].recall == 1.0

    def test_totais_por_cwe_somam_o_geral(self, metricas):
        por_cwe = [m for nome, m in metricas.items() if nome != "geral"]
        assert sum(m.vp for m in por_cwe) == metricas["geral"].vp
        assert sum(m.fn for m in por_cwe) == metricas["geral"].fn


class TestTabela:
    def test_traz_denominador_da_varredura(self):
        varredura = executar(DIRETORIO_AMOSTRAS)
        tabela = formatar_tabela(avaliar(DIRETORIO_AMOSTRAS, varredura), varredura)
        assert "Arquivos analisados" in tabela
        assert "Arquivos com falha" in tabela

    def test_declara_o_limite_de_validade_dos_numeros(self):
        varredura = executar(DIRETORIO_AMOSTRAS)
        tabela = formatar_tabela(avaliar(DIRETORIO_AMOSTRAS, varredura), varredura)
        assert "NAO generalizacao" in AVISO_DE_ESCOPO
        assert "consistencia interna" in tabela

    def test_geral_aparece_por_ultimo(self):
        varredura = executar(DIRETORIO_AMOSTRAS)
        tabela = formatar_tabela(avaliar(DIRETORIO_AMOSTRAS, varredura), varredura)
        linhas = [l for l in tabela.splitlines() if l.startswith(" CWE-") or l.startswith(" geral")]
        assert linhas[-1].startswith(" geral")


class TestExecucao:
    def test_main_roda_sobre_o_corpus(self, capsys):
        assert main([str(DIRETORIO_AMOSTRAS)]) == 0
        assert "avaliacao contra corpus rotulado" in capsys.readouterr().out

    def test_main_reclama_de_caminho_inexistente(self, capsys):
        assert main(["nao/existe"]) == 2
        assert "caminho nao encontrado" in capsys.readouterr().err
