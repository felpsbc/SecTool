"""Contraparte com controle de acesso. Nenhum candidato esperado aqui."""

import sqlite3

from flask import Flask, jsonify, request
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/pedido/<int:pedido_id>")
@login_required
def ver_pedido(pedido_id):
    # A consulta amarra o objeto ao dono: nao ha referencia insegura.
    pedido = Pedido.query.filter_by(id=pedido_id, user=current_user).first()
    return jsonify(pedido.para_dict())


@app.route("/fatura/<fatura_id>")
@permission_required("ver_fatura")
def ver_fatura(fatura_id):
    # Decorator de autorizacao declarado: candidato suprimido.
    fatura = Fatura.objects.get(pk=fatura_id)
    return jsonify(fatura.para_dict())


@app.route("/documento")
def ver_documento():
    documento = Documento.query.filter_by(owner_id=current_user.id).all()
    return jsonify([d.para_dict() for d in documento])


@app.route("/contrato/<contrato_id>")
def ver_contrato(contrato_id):
    cursor = sqlite3.connect("app.db").cursor()
    cursor.execute(
        "SELECT * FROM contratos WHERE id = ? AND user_id = ?",
        (contrato_id, current_user.id),
    )
    return jsonify(cursor.fetchone())


@app.route("/config")
def config():
    # Lookup em dicionario nao e consulta a modelo.
    return jsonify(CONFIGURACOES.get(request.args["chave"]))
