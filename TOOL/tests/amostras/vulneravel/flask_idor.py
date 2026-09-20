"""Amostra Flask com candidatos a IDOR (gabarito inline).

Nao executar. Cada candidato carrega o marcador de gabarito na sua propria
linha; ver tests/conftest.py. Sao CANDIDATOS: a ferramenta nao afirma que
sao vulneraveis.
"""

import sqlite3

from flask import Flask, jsonify, request
from flask_login import login_required

app = Flask(__name__)


@app.route("/pedido/<int:pedido_id>")
def ver_pedido(pedido_id):
    pedido = Pedido.query.get(pedido_id)  # achado: CWE-639
    return jsonify(pedido.para_dict())


@app.route("/fatura/<fatura_id>")
@login_required
def ver_fatura(fatura_id):
    # login_required autentica, mas nao autoriza: continua candidato.
    fatura = Fatura.objects.filter(id=fatura_id)  # achado: CWE-639
    return jsonify(list(fatura))


@app.route("/documento")
def ver_documento():
    documento_id = request.args["doc"]
    documento = get_object_or_404(Documento, pk=documento_id)  # achado: CWE-639
    return jsonify(documento.para_dict())


@app.route("/contrato/<contrato_id>")
def ver_contrato(contrato_id):
    cursor = sqlite3.connect("app.db").cursor()
    cursor.execute("SELECT * FROM contratos WHERE id = ?", (contrato_id,))  # achado: CWE-639
    return jsonify(cursor.fetchone())


@app.route("/perfil/<perfil_id>")
def ver_perfil(perfil_id):
    perfil = Perfil.query.filter_by(id=perfil_id).first()  # achado: CWE-639
    return jsonify(perfil.para_dict())
