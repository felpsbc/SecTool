"""Fase 20: o arquivo do roteiro de teste do site produz o resultado documentado.

docs/teste/ROTEIRO_DE_TESTE.md diz o que a pessoa deve ver na pagina ao
enviar docs/teste/app_vulneravel.py. Se o motor mudar, este teste avisa que
o roteiro precisa ser atualizado junto.
"""

from pathlib import Path

import pytest

from owaspscan.varredura import executar

APP = Path(__file__).resolve().parents[2] / "docs" / "teste" / "app_vulneravel.py"

# (linha, cwe, confianca) exatamente como na tabela do roteiro
ESPERADO = {
    (12, "CWE-798", "alta"),
    (24, "CWE-89", "alta"),
    (32, "CWE-79", "alta"),
    (38, "CWE-601", "alta"),
    (45, "CWE-22", "alta"),
    (24, "CWE-639", "baixa"),
    (52, "CWE-639", "baixa"),
    (61, "CWE-639", "baixa"),
}


@pytest.fixture(scope="module")
def achados():
    if not APP.exists():
        pytest.skip("docs/teste fora do checkout (TOOL instalado isolado)")
    return executar(APP).achados


def test_achados_batem_com_o_roteiro(achados):
    assert {(a.linha, a.cwe, a.confianca) for a in achados} == ESPERADO


def test_controle_negativo_parametrizado_nao_gera_sqli(achados):
    assert not [a for a in achados if a.cwe == "CWE-89" and a.linha == 61]


def test_idor_e_sempre_candidato_de_baixa_confianca(achados):
    assert all(a.confianca == "baixa" for a in achados if a.cwe == "CWE-639")
