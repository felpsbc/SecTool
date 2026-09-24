"""API autenticada por token no cabecalho: CSRF nao se aplica.

Nenhum achado de CWE-352 esperado: o navegador nao envia o cabecalho
Authorization sozinho, entao nao ha requisicao forjada com credencial.
"""

from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required

api = Flask(__name__)


@api.route("/api/pedidos", methods=["POST"])
@jwt_required()
def criar_pedido():
    return jsonify(id=int(request.json["produto"]))
