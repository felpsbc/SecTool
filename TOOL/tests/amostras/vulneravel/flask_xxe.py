"""Amostra Flask vulneravel a XXE (gabarito inline).

Nao executar. As views sao autenticadas e o app tem CSRFProtect para que a
amostra isole a CWE-611.
"""

import xml.sax
from xml.sax.handler import feature_external_ges

from flask import Flask, jsonify, request
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect
from lxml import etree

app = Flask(__name__)
csrf = CSRFProtect(app)

PARSER_PERMISSIVO = etree.XMLParser(resolve_entities=True)  # achado: CWE-611


@app.route("/importar", methods=["POST"])
@login_required
def importar():
    # Parser padrao do lxml sobre o corpo da requisicao.
    documento = etree.fromstring(request.data)  # achado: CWE-611
    return jsonify(documento.findtext("nome"))


@app.route("/importar-arquivo", methods=["POST"])
@login_required
def importar_arquivo():
    arvore = etree.parse(request.files["xml"], PARSER_PERMISSIVO)
    return jsonify(arvore.getroot().tag)


@app.route("/rede", methods=["POST"])
@login_required
def rede():
    parser = etree.XMLParser(no_network=False)  # achado: CWE-611
    return jsonify(etree.fromstring(request.data, parser=parser).tag)


def processar_sax(fluxo, handler):
    leitor = xml.sax.make_parser()
    leitor.setFeature(feature_external_ges, True)  # achado: CWE-611
    leitor.setContentHandler(handler)
    leitor.parse(fluxo)
