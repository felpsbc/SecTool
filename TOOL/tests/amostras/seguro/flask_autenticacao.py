"""Contraparte segura de autenticacao. Nenhum achado de A07/CWE-916/CWE-256."""

import hashlib
import os
from datetime import timedelta

import bcrypt
import jwt
from flask import Flask, jsonify, make_response, request
from flask_limiter import Limiter
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(app)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=15),
)
CHAVE = os.environ["CHAVE_JWT"]


def usuario_do_token(token):
    return jwt.decode(token, CHAVE, algorithms=["HS256"])["sub"]


def checksum(dados):
    # sha256 sobre conteudo, nao sobre senha: uso legitimo.
    return hashlib.sha256(dados).hexdigest()


@app.route("/cadastro", methods=["POST"])
def cadastro():
    senha = request.form["senha"]
    usuario = Usuario(email=request.form["email"], senha=generate_password_hash(senha))
    usuario.senha_bcrypt = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
    return jsonify(ok=True)


@app.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    usuario = Usuario.query.filter_by(email=request.form["email"]).first()
    if usuario and check_password_hash(usuario.senha, request.form["senha"]):
        resposta = make_response(jsonify(ok=True))
        resposta.set_cookie(
            "session_token", gerar_token(usuario), secure=True, httponly=True, samesite="Lax"
        )
        return resposta
    return jsonify(ok=False), 401


@app.route("/preferencias", methods=["POST"])
@login_required
def preferencias():
    # Cookie nao sensivel: nao exige Secure/HttpOnly.
    resposta = make_response(jsonify(ok=True))
    resposta.set_cookie("tema", "escuro")
    return resposta
