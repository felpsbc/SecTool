"""Fase 7: resumo executivo em texto e JSON."""

import json
from datetime import datetime

import pytest

from owaspscan.achado import criar_achado
from owaspscan.analisador import FalhaDeLeitura
from owaspscan.relatorio import (
    Varredura,
    formatar_texto,
    ordenar,
    para_dict,
    resumir,
)

MOMENTO = datetime(2026, 9, 16, 22, 50, 0)


def achado(cwe="CWE-89", severidade="alta", confianca="alta", arquivo="app.py", linha=10):
    return criar_achado(
        arquivo=arquivo,
        linha=linha,
        cwe=cwe,
        severidade=severidade,
        confianca=confianca,
        trecho="trecho",
        descricao="descricao",
        recomendacao=f"recomendacao para {cwe}",
    )


def varredura(*achados, falhas=(), arquivos=3):
    return Varredura(
        raiz="projeto/",
        achados=tuple(achados),
        arquivos_analisados=arquivos,
        falhas=tuple(falhas),
        momento=MOMENTO,
    )


class TestSeparacaoDeAchados:
    def test_confianca_baixa_e_candidato(self):
        v = varredura(
            achado(),
            achado(cwe="CWE-639", severidade="media", confianca="baixa"),
        )
        assert len(v.confirmados) == 1
        assert len(v.candidatos) == 1
        assert v.candidatos[0].cwe == "CWE-639"

    def test_o_corte_e_a_confianca_e_nao_a_cwe(self):
        # Um achado de SQLi com confianca baixa cairia entre os candidatos.
        v = varredura(achado(confianca="baixa"))
        assert v.candidatos[0].cwe == "CWE-89"
        assert v.confirmados == ()

    def test_confianca_media_conta_como_rastreado(self):
        v = varredura(achado(confianca="media"))
        assert len(v.confirmados) == 1


class TestResumo:
    def test_contagens_por_dimensao(self):
        resumo = resumir(
            varredura(
                achado(),
                achado(linha=20),
                achado(cwe="CWE-79", severidade="media", arquivo="views.py"),
                achado(cwe="CWE-639", severidade="media", confianca="baixa"),
            )
        )
        assert resumo.total == 4
        assert resumo.confirmados == 3
        assert resumo.candidatos == 1
        assert resumo.por_severidade == {"alta": 2, "media": 2}
        assert resumo.por_cwe == {"CWE-89": 2, "CWE-639": 1, "CWE-79": 1}
        assert resumo.por_owasp == {
            "A03:2021 Injection": 3,
            "A01:2021 Broken Access Control": 1,
        }
        assert resumo.por_arquivo == {"app.py": 3, "views.py": 1}
        assert resumo.arquivos_com_achado == 2

    def test_varredura_vazia(self):
        resumo = resumir(varredura())
        assert resumo.total == 0
        assert resumo.por_severidade == {}
        assert resumo.arquivos_com_achado == 0


class TestOrdenacao:
    def test_severidade_vem_antes_de_arquivo(self):
        ordenados = ordenar(
            [
                achado(cwe="CWE-79", severidade="media", arquivo="a.py"),
                achado(severidade="alta", arquivo="z.py"),
            ]
        )
        assert [a.arquivo for a in ordenados] == ["z.py", "a.py"]

    def test_confianca_desempata_dentro_da_severidade(self):
        ordenados = ordenar(
            [
                achado(severidade="media", confianca="baixa", arquivo="a.py"),
                achado(severidade="media", confianca="alta", arquivo="z.py"),
            ]
        )
        assert [a.confianca for a in ordenados] == ["alta", "baixa"]

    def test_linha_desempata_dentro_do_arquivo(self):
        ordenados = ordenar([achado(linha=30), achado(linha=5)])
        assert [a.linha for a in ordenados] == [5, 30]


class TestSaidaEmTexto:
    def test_cabecalho_traz_metadados_da_execucao(self):
        texto = formatar_texto(varredura(achado()))
        assert "projeto/" in texto
        assert "2026-09-16 22:50:00" in texto
        assert "3 analisados" in texto

    def test_secoes_sao_separadas(self):
        texto = formatar_texto(
            varredura(achado(), achado(cwe="CWE-639", severidade="media", confianca="baixa"))
        )
        posicao_achados = texto.index("ACHADOS RASTREADOS POR TAINT")
        posicao_candidatos = texto.index("CANDIDATOS HEURISTICOS")
        assert posicao_achados < posicao_candidatos

    def test_secao_de_candidatos_avisa_que_nao_afirma_vulnerabilidade(self):
        texto = formatar_texto(
            varredura(achado(cwe="CWE-639", severidade="media", confianca="baixa"))
        )
        assert "NAO afirmam vulnerabilidade" in texto

    def test_candidato_nao_aparece_na_secao_de_achados(self):
        texto = formatar_texto(
            varredura(achado(cwe="CWE-639", severidade="media", confianca="baixa"))
        )
        secao_achados = texto.split("CANDIDATOS HEURISTICOS")[0]
        assert "CWE-639" not in secao_achados

    def test_recomendacao_aparece_uma_vez_por_cwe(self):
        texto = formatar_texto(varredura(achado(linha=1), achado(linha=2), achado(linha=3)))
        assert texto.count("recomendacao para CWE-89") == 1

    def test_varredura_sem_achados_diz_isso_nas_duas_secoes(self):
        texto = formatar_texto(varredura())
        assert "Nenhum achado rastreado por taint." in texto
        assert "Nenhum candidato heuristico." in texto

    def test_falhas_de_leitura_aparecem_no_relatorio(self):
        texto = formatar_texto(
            varredura(
                falhas=[
                    FalhaDeLeitura(
                        arquivo="quebrado.py",
                        motivo="sintaxe",
                        mensagem="invalid syntax",
                        linha=7,
                    )
                ]
            )
        )
        assert "ARQUIVOS NAO ANALISADOS" in texto
        assert "quebrado.py:7 [sintaxe] invalid syntax" in texto

    def test_saida_e_deterministica(self):
        v = varredura(achado(), achado(cwe="CWE-79", severidade="media"))
        assert formatar_texto(v) == formatar_texto(v)


class TestSaidaEmJson:
    def test_estrutura_principal(self):
        dados = para_dict(varredura(achado()))
        assert dados["ferramenta"] == "owasp-scan"
        assert dados["raiz"] == "projeto/"
        assert dados["momento"] == "2026-09-16T22:50:00"
        assert set(dados) == {
            "ferramenta",
            "versao",
            "raiz",
            "momento",
            "varredura",
            "resumo",
            "achados",
        }

    def test_achados_saem_nos_dez_campos_do_contrato(self):
        dados = para_dict(varredura(achado()))
        assert list(dados["achados"][0]) == [
            "arquivo",
            "linha",
            "cwe",
            "owasp",
            "vulnerabilidade",
            "severidade",
            "confianca",
            "trecho",
            "descricao",
            "recomendacao",
        ]

    def test_metadados_preservam_o_denominador_da_varredura(self):
        dados = para_dict(
            varredura(
                achado(),
                falhas=[
                    FalhaDeLeitura(arquivo="x.py", motivo="sintaxe", mensagem="erro", linha=2)
                ],
            )
        )
        assert dados["varredura"]["arquivos_analisados"] == 3
        assert dados["varredura"]["arquivos_com_falha"] == 1
        assert dados["varredura"]["falhas"][0]["motivo"] == "sintaxe"

    def test_resumo_separa_rastreados_de_candidatos(self):
        dados = para_dict(
            varredura(achado(), achado(cwe="CWE-639", severidade="media", confianca="baixa"))
        )
        assert dados["resumo"]["rastreados_por_taint"] == 1
        assert dados["resumo"]["candidatos_heuristicos"] == 1

    def test_json_e_serializavel(self):
        texto = json.dumps(para_dict(varredura(achado())), ensure_ascii=False)
        assert json.loads(texto)["achados"][0]["cwe"] == "CWE-89"
