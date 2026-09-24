"""Amostra Flask sem protecao CSRF (gabarito inline). Nao executar."""

from flask import Flask, jsonify, request
from flask_login import login_required

app = Flask(__name__)  # achado: CWE-352
app.config["WTF_CSRF_ENABLED"] = False  # achado: CWE-352


@app.route("/transferir", methods=["POST"])
@login_required
def transferir():
    return jsonify(ok=True, valor=int(request.form["valor"]))
