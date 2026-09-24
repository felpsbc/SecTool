"""Fase 11: detector de XML External Entity (CWE-611)."""

import pytest

from conftest import (
    DIRETORIO_AMOSTRAS,
    linhas_esperadas,
    rodar_detector,
    rodar_detector_em_arquivo,
)
from owaspscan.detectores.xxe import DetectorXxe

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_xxe.py"
SEGURO = DIRETORIO_AMOSTRAS / "seguro" / "flask_xxe.py"


def detectar(fonte: str):
    return rodar_detector(DetectorXxe(), fonte)


class TestAmostras:
    def test_vulneravel_bate_com_o_gabarito(self):
        achados = rodar_detector_em_arquivo(DetectorXxe(), VULNERAVEL)
        assert sorted(a.linha for a in achados) == linhas_esperadas(
            VULNERAVEL, "CWE-611"
        )

    def test_seguro_nao_tem_achado(self):
        assert rodar_detector_em_arquivo(DetectorXxe(), SEGURO) == []

    def test_classificacao_segue_o_contrato(self):
        for achado in rodar_detector_em_arquivo(DetectorXxe(), VULNERAVEL):
            assert achado.owasp == "A05:2021 Security Misconfiguration"
            assert achado.vulnerabilidade == "XML External Entity (XXE)"
            assert achado.severidade == "alta"


class TestConfiguracaoDoParser:
    @pytest.mark.parametrize(
        "argumentos",
        ["resolve_entities=True", "no_network=False", "load_dtd=True"],
    )
    def test_parser_inseguro_e_alta_confianca(self, argumentos):
        achados = detectar(f"from lxml import etree\np = etree.XMLParser({argumentos})\n")
        assert [a.confianca for a in achados] == ["alta"]

    def test_load_dtd_com_entidades_desligadas_e_seguro(self):
        fonte = (
            "from lxml import etree\n"
            "p = etree.XMLParser(load_dtd=True, resolve_entities=False)\n"
        )
        assert detectar(fonte) == []

    def test_xmlparser_de_outra_biblioteca_nao_e_lxml(self):
        fonte = "from xml.etree.ElementTree import XMLParser\np = XMLParser(resolve_entities=True)\n"
        assert detectar(fonte) == []

    def test_sax_com_feature_em_string(self):
        fonte = (
            "import xml.sax\n"
            "p = xml.sax.make_parser()\n"
            "p.setFeature('http://xml.org/sax/features/external-general-entities', True)\n"
        )
        assert [a.linha for a in detectar(fonte)] == [3]

    def test_sax_com_feature_desligada_e_seguro(self):
        fonte = "p.setFeature(feature_external_ges, False)\n"
        assert detectar(fonte) == []


class TestParseDeDadoNaoConfiavel:
    ROTA = (
        "from flask import request\nfrom lxml import etree\n"
        "@app.route('/x', methods=['POST'])\ndef v():\n{corpo}\n"
    )

    def _rota(self, corpo: str):
        return detectar(self.ROTA.format(corpo=corpo))

    def test_parser_padrao_e_confianca_media(self):
        achados = self._rota("    return etree.fromstring(request.data)")
        assert [a.confianca for a in achados] == ["media"]
        assert "lxml anterior a 5.0" in achados[0].descricao

    def test_parser_seguro_inline_suprime(self):
        corpo = (
            "    return etree.fromstring(request.data, "
            "etree.XMLParser(resolve_entities=False))"
        )
        assert self._rota(corpo) == []

    def test_parser_nao_resolvido_nao_acusa(self):
        assert self._rota("    return etree.fromstring(request.data, parser=p)") == []

    def test_dado_local_nao_acusa(self):
        assert self._rota("    return etree.parse('fixo.xml')") == []

    def test_stdlib_nao_e_xxe(self):
        fonte = (
            "import xml.etree.ElementTree as ET\nfrom flask import request\n"
            "@app.post('/x')\ndef v():\n    return ET.fromstring(request.data)\n"
        )
        assert detectar(fonte) == []

    def test_objectify_tambem_e_lxml(self):
        fonte = (
            "from lxml import objectify\nfrom flask import request\n"
            "@app.post('/x')\ndef v():\n    return objectify.fromstring(request.data)\n"
        )
        assert len(detectar(fonte)) == 1
