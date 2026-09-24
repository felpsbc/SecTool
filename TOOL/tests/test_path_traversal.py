"""Fase 12: detector de Path Traversal (CWE-22)."""

import pytest

from conftest import (
    DIRETORIO_AMOSTRAS,
    linhas_de_limitacao,
    linhas_esperadas,
    rodar_detector,
    rodar_detector_em_arquivo,
)
from owaspscan.detectores.path_traversal import DetectorPathTraversal

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_path_traversal.py"
SEGURO = DIRETORIO_AMOSTRAS / "seguro" / "flask_path_traversal.py"

ROTA = (
    "import os, shutil\nfrom pathlib import Path\nfrom flask import request\n"
    "@app.route('/x')\ndef v():\n    nome = request.args['n']\n{corpo}\n"
)


def detectar(corpo: str):
    return rodar_detector(DetectorPathTraversal(), ROTA.format(corpo=corpo))


class TestAmostras:
    def test_vulneravel_bate_com_o_gabarito(self):
        achados = rodar_detector_em_arquivo(DetectorPathTraversal(), VULNERAVEL)
        assert sorted(a.linha for a in achados) == linhas_esperadas(VULNERAVEL, "CWE-22")

    def test_limitacao_interprocedural_continua_nao_detectada(self):
        linhas = {a.linha for a in rodar_detector_em_arquivo(DetectorPathTraversal(), VULNERAVEL)}
        assert set(linhas_de_limitacao(VULNERAVEL)).isdisjoint(linhas)

    def test_seguro_nao_tem_achado(self):
        assert rodar_detector_em_arquivo(DetectorPathTraversal(), SEGURO) == []

    def test_classificacao(self):
        for achado in rodar_detector_em_arquivo(DetectorPathTraversal(), VULNERAVEL):
            assert achado.owasp == "A01:2021 Broken Access Control"
            assert achado.vulnerabilidade == "Path Traversal"
            assert achado.severidade == "alta"


class TestSinks:
    @pytest.mark.parametrize(
        "corpo",
        [
            "    open(nome)",
            "    os.remove(nome)",
            "    shutil.copy('a', nome)",
            "    Path(nome).write_text('x')",
            "    send_file(nome)",
        ],
    )
    def test_sinks_reconhecidos(self, corpo):
        assert len(detectar(corpo)) == 1

    def test_join_mantem_confianca_alta(self):
        assert [a.confianca for a in detectar("    open(os.path.join('/b', nome))")] == ["alta"]

    def test_remove_de_lista_nao_e_arquivo(self):
        assert detectar("    lista = []\n    lista.remove(nome)") == []

    def test_open_com_literal_nao_acusa(self):
        assert detectar("    open('/etc/app.conf')") == []


class TestDefesas:
    @pytest.mark.parametrize(
        "corpo",
        [
            "    open(secure_filename(nome))",
            "    open(os.path.basename(nome))",
            "    open(safe_join('/b', nome))",
            "    open(f'/b/{int(nome)}.txt')",
        ],
    )
    def test_sanitizadores_removem_o_achado(self, corpo):
        assert detectar(corpo) == []

    def test_guarda_com_realpath_suprime(self):
        corpo = (
            "    d = os.path.realpath(os.path.join('/b', nome))\n"
            "    if not d.startswith('/b/'):\n        abort(400)\n    open(d)"
        )
        assert detectar(corpo) == []

    def test_guarda_sem_canonicalizar_nao_suprime(self):
        corpo = (
            "    d = os.path.join('/b', nome)\n"
            "    if not d.startswith('/b/'):\n        abort(400)\n    open(d)"
        )
        assert len(detectar(corpo)) == 1
