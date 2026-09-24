"""Contraparte segura de CSRF. Nenhum achado de CWE-352 esperado."""

from flask import Flask, jsonify, request
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.route("/transferir", methods=["POST"])
@login_required
def transferir():
    return jsonify(ok=True, valor=int(request.form["valor"]))
