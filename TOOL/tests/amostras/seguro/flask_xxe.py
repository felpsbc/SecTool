"""Contraparte segura de XXE. Nenhum achado de CWE-611 esperado aqui."""

import xml.etree.ElementTree as ET

import defusedxml.ElementTree as DET
from flask import Flask, jsonify, request
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect
from lxml import etree

app = Flask(__name__)
csrf = CSRFProtect(app)

PARSER_SEGURO = etree.XMLParser(resolve_entities=False, no_network=True)


@app.route("/importar", methods=["POST"])
@login_required
def importar():
    # defusedxml bloqueia entidades externas e expansao recursiva.
    return jsonify(DET.fromstring(request.data).findtext("nome"))


@app.route("/importar-lxml", methods=["POST"])
@login_required
def importar_lxml():
    # Parser declarado com resolve_entities=False.
    return jsonify(etree.fromstring(request.data, PARSER_SEGURO).tag)


@app.route("/importar-stdlib", methods=["POST"])
@login_required
def importar_stdlib():
    # xml.etree nao resolve entidades externas desde o Python 3.7.1.
    return jsonify(ET.fromstring(request.data).tag)


def configuracao_local():
    # lxml sobre arquivo fixo do servidor: nao ha dado da requisicao.
    return jsonify(etree.parse("config/padrao.xml").getroot())
