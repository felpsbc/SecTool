"""Amostra Flask com falhas de autenticacao (gabarito inline). Nao executar."""

import hashlib
import os
from datetime import timedelta

import jwt
from flask import Flask, jsonify, make_response, request
from flask_login import current_user, login_required
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config["SESSION_COOKIE_SECURE"] = False  # achado: CWE-614
app.config["SESSION_COOKIE_HTTPONLY"] = False  # achado: CWE-1004
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)  # achado: CWE-613
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False  # achado: CWE-613
CHAVE = os.environ["CHAVE_JWT"]


def usuario_do_token(token):
    dados = jwt.decode(token, options={"verify_signature": False})  # achado: CWE-287
    return dados["sub"]


def token_legado(token):
    return jwt.decode(token, CHAVE, algorithms=["HS256", "none"])  # achado: CWE-287


@app.route("/cadastro", methods=["POST"])
def cadastro():
    senha = request.form["senha"]
    usuario = Usuario(email=request.form["email"], senha=senha)  # achado: CWE-256
    usuario.senha_hash = hashlib.md5(senha.encode()).hexdigest()  # achado: CWE-916
    return jsonify(ok=True)


@app.route("/login", methods=["POST"])
def login():  # achado: CWE-307
    usuario = Usuario.query.filter_by(email=request.form["email"]).first()
    if usuario and usuario.senha == request.form["senha"]:  # achado: CWE-256
        resposta = make_response(jsonify(ok=True))
        resposta.set_cookie("session_token", gerar_token(usuario))  # achado: CWE-614, CWE-1004
        return resposta
    return jsonify(ok=False), 401


@app.route("/perfil/senha", methods=["POST"])
@login_required
def trocar_senha():
    resumo = hashlib.sha256()
    resumo.update(request.form["nova_senha"].encode())  # achado: CWE-916
    current_user.password = resumo.hexdigest()
    return jsonify(ok=True)
