"""Fase 12: detector de Open Redirect (CWE-601)."""

import pytest

from conftest import (
    DIRETORIO_AMOSTRAS,
    linhas_esperadas,
    rodar_detector,
    rodar_detector_em_arquivo,
)
from owaspscan.detectores.open_redirect import DetectorOpenRedirect

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_open_redirect.py"
SEGURO = DIRETORIO_AMOSTRAS / "seguro" / "flask_open_redirect.py"

ROTA = "from flask import request, redirect\n@app.route('/x')\ndef v():\n{corpo}\n"


def detectar(corpo: str):
    return rodar_detector(DetectorOpenRedirect(), ROTA.format(corpo=corpo))


class TestAmostras:
    def test_vulneravel_bate_com_o_gabarito(self):
        achados = rodar_detector_em_arquivo(DetectorOpenRedirect(), VULNERAVEL)
        assert sorted(a.linha for a in achados) == linhas_esperadas(VULNERAVEL, "CWE-601")

    def test_seguro_nao_tem_achado(self):
        assert rodar_detector_em_arquivo(DetectorOpenRedirect(), SEGURO) == []

    def test_classificacao(self):
        for achado in rodar_detector_em_arquivo(DetectorOpenRedirect(), VULNERAVEL):
            assert achado.owasp == "A01:2021 Broken Access Control"
            assert achado.vulnerabilidade == "Open Redirect"
            assert achado.severidade == "media"


class TestDeteccao:
    def test_next_da_query_string(self):
        achados = detectar("    return redirect(request.args['next'])")
        assert [a.confianca for a in achados] == ["alta"]

    def test_destino_literal_nao_acusa(self):
        assert detectar("    return redirect('/inicio')") == []

    def test_url_for_neutraliza(self):
        assert detectar("    return redirect(url_for('a', n=request.args['n']))") == []

    @pytest.mark.parametrize(
        "validacao",
        ["is_safe_url(d)", "url_has_allowed_host_and_scheme(d, None)", "not urlparse(d).netloc"],
    )
    def test_validacao_em_condicao_suprime(self, validacao):
        corpo = f"    d = request.args['next']\n    if {validacao}:\n        return redirect(d)"
        assert detectar(corpo) == []

    def test_startswith_barra_nao_e_validacao(self):
        corpo = "    d = request.args['next']\n    if d.startswith('/'):\n        return redirect(d)"
        assert len(detectar(corpo)) == 1
