"""Contraparte segura de autorizacao. Nenhum candidato a CWE-862 esperado."""

from flask import Flask, abort, jsonify, request
from flask_login import current_user, login_required
from flask_security import roles_required
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.route("/login", methods=["POST"])
def login():  # achado: CWE-307
    # Rota publica por natureza.
    return jsonify(autenticar(request.form["usuario"], request.form["senha"]))


@app.route("/comentarios", methods=["POST"])
@login_required
def comentar():
    return jsonify(salvar_comentario(request.form["texto"]))


@app.route("/admin/usuarios")
@roles_required("admin")
def listar_usuarios():
    return jsonify(todos_os_usuarios())


@app.route("/admin/config", methods=["POST"])
@login_required
def configurar():
    if not current_user.is_admin:
        abort(403)
    return jsonify(ok=True)


@app.route("/produtos")
def listar_produtos():
    # Leitura publica: nao altera estado nem e administrativa.
    return jsonify(catalogo())
