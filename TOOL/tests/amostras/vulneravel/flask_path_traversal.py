"""Amostra Flask vulneravel a Path Traversal (gabarito inline).

Nao executar. Views autenticadas e CSRFProtect para isolar a CWE-22.
"""

import os
import shutil
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
BASE = "/srv/arquivos"


@app.route("/baixar")
@login_required
def baixar():
    nome = request.args.get("arquivo")
    return send_file(os.path.join(BASE, nome))  # achado: CWE-22


@app.route("/ler/<nome>")
@login_required
def ler(nome):
    with open(BASE + "/" + nome) as arquivo:  # achado: CWE-22
        return jsonify(conteudo=arquivo.read())


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    enviado = request.files["documento"]
    enviado.save(os.path.join(BASE, enviado.filename))  # achado: CWE-22
    return jsonify(ok=True)


@app.route("/apagar", methods=["POST"])
@login_required
def apagar():
    alvo = request.form["pasta"]
    shutil.rmtree(Path(BASE) / alvo)  # achado: CWE-22
    return jsonify(ok=True)


@app.route("/relatorio/<nome>")
@login_required
def relatorio(nome):
    # Comparar sem canonicalizar nao confina: "../" passa pelo startswith.
    caminho = os.path.join(BASE, nome)
    if not caminho.startswith(BASE):
        return jsonify(erro="negado"), 400
    return jsonify(Path(caminho).read_text())  # achado: CWE-22


def _ler_de(caminho):
    with open(caminho) as arquivo:  # limitacao: CWE-22 fluxo interprocedural
        return arquivo.read()


@app.route("/indireto")
@login_required
def indireto():
    return jsonify(_ler_de(request.args["arquivo"]))
