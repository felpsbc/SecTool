"""Amostra Flask com candidatos a rota sem autorizacao (gabarito inline).

Nao executar. Sao CANDIDATOS: o controle de acesso pode existir fora do
arquivo. CSRFProtect presente para isolar a CWE-862.
"""

from flask import Blueprint, Flask, jsonify, request
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.route("/comentarios", methods=["POST"])
def comentar():  # achado: CWE-862
    return jsonify(salvar_comentario(request.form["texto"]))


@app.delete("/posts/<int:post_id>")
def apagar_post(post_id):  # achado: CWE-862
    remover_post(post_id)
    return jsonify(ok=True)


@app.route("/admin/usuarios")
@login_required
def listar_usuarios():  # achado: CWE-862
    # Autenticado, mas sem papel: qualquer usuario logado ve a lista.
    return jsonify(todos_os_usuarios())


@app.route("/admin/config", methods=["GET", "POST"])
def configurar():  # achado: CWE-862
    return jsonify(ok=True)
