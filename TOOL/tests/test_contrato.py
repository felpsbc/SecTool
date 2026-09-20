"""Fase 0: o contrato interno de achado e o mapa CWE -> OWASP.

Os valores esperados sao escritos literalmente aqui, copiados do CLAUDE.md,
para que o teste seja um oraculo independente do codigo de producao.
"""

import json

import pytest

from owaspscan.achado import (
    MAPA_CWE_OWASP,
    Achado,
    ClassificacaoInvalida,
    campos_do_achado,
    criar_achado,
)

# Copiado do CLAUDE.md, secao "Formato do achado".
CAMPOS_ESPERADOS = (
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
)

# Copiado do CLAUDE.md, secao "Mapeamento CWE -> OWASP".
MAPEAMENTO_ESPERADO = {
    "CWE-89": ("A03:2021 Injection", "SQL Injection"),
    "CWE-79": ("A03:2021 Injection", "Cross-Site Scripting"),
    "CWE-639": ("A01:2021 Broken Access Control", "IDOR"),
}


def achado_exemplo(**sobrescritas):
    padrao = dict(
        arquivo="app/views.py",
        linha=42,
        cwe="CWE-89",
        severidade="alta",
        confianca="alta",
        trecho='cursor.execute("SELECT * FROM u WHERE id = " + id_usuario)',
        descricao="Query montada por concatenacao com dado da requisicao.",
        recomendacao="Usar query parametrizada: cursor.execute(sql, (id_usuario,)).",
    )
    padrao.update(sobrescritas)
    return criar_achado(**padrao)


class TestCamposDoContrato:
    def test_dataclass_tem_exatamente_os_campos_do_contrato(self):
        assert campos_do_achado() == CAMPOS_ESPERADOS

    def test_serializacao_preserva_ordem_e_campos(self):
        dados = achado_exemplo().para_dict()
        assert tuple(dados) == CAMPOS_ESPERADOS

    def test_achado_serializa_para_json(self):
        texto = json.dumps(achado_exemplo().para_dict(), ensure_ascii=False)
        assert json.loads(texto)["cwe"] == "CWE-89"

    def test_achado_e_imutavel(self):
        achado = achado_exemplo()
        with pytest.raises(Exception):
            achado.severidade = "baixa"


class TestMapeamentoCweOwasp:
    def test_mapa_cobre_exatamente_as_cwes_previstas(self):
        assert set(MAPA_CWE_OWASP) == set(MAPEAMENTO_ESPERADO)

    @pytest.mark.parametrize("cwe", sorted(MAPEAMENTO_ESPERADO))
    def test_cada_cwe_mapeia_para_owasp_e_nome_corretos(self, cwe):
        owasp, vulnerabilidade = MAPEAMENTO_ESPERADO[cwe]
        classe = MAPA_CWE_OWASP[cwe]
        assert classe.owasp == owasp
        assert classe.vulnerabilidade == vulnerabilidade

    @pytest.mark.parametrize("cwe", sorted(MAPEAMENTO_ESPERADO))
    def test_criar_achado_deriva_classificacao_do_mapa(self, cwe):
        owasp, vulnerabilidade = MAPEAMENTO_ESPERADO[cwe]
        achado = achado_exemplo(cwe=cwe)
        assert achado.owasp == owasp
        assert achado.vulnerabilidade == vulnerabilidade


class TestClassificacaoInvalida:
    def test_cwe_desconhecida_e_rejeitada(self):
        with pytest.raises(ClassificacaoInvalida, match="CWE desconhecida"):
            achado_exemplo(cwe="CWE-1234")

    def test_owasp_inventado_e_rejeitado(self):
        with pytest.raises(ClassificacaoInvalida, match="A03:2021 Injection"):
            Achado(
                arquivo="app/views.py",
                linha=1,
                cwe="CWE-89",
                owasp="A10:2021 SSRF",
                vulnerabilidade="SQL Injection",
                severidade="alta",
                confianca="alta",
                trecho="x",
                descricao="x",
                recomendacao="x",
            )

    def test_nome_de_vulnerabilidade_inventado_e_rejeitado(self):
        with pytest.raises(ClassificacaoInvalida):
            Achado(
                arquivo="app/views.py",
                linha=1,
                cwe="CWE-79",
                owasp="A03:2021 Injection",
                vulnerabilidade="XSS refletido",
                severidade="media",
                confianca="media",
                trecho="x",
                descricao="x",
                recomendacao="x",
            )

    @pytest.mark.parametrize("valor", ["critica", "ALTA", "", "high"])
    def test_severidade_fora_do_vocabulario_e_rejeitada(self, valor):
        with pytest.raises(ClassificacaoInvalida, match="severidade"):
            achado_exemplo(severidade=valor)

    @pytest.mark.parametrize("valor", ["certa", "MEDIA", "", "low"])
    def test_confianca_fora_do_vocabulario_e_rejeitada(self, valor):
        with pytest.raises(ClassificacaoInvalida, match="confianca"):
            achado_exemplo(confianca=valor)

    def test_linha_invalida_e_rejeitada(self):
        with pytest.raises(ClassificacaoInvalida, match="linha"):
            achado_exemplo(linha=0)
