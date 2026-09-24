"""Contraparte segura de Path Traversal. Nenhum achado de CWE-22 esperado."""

import os
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory
from flask_login import login_required
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

app = Flask(__name__)
csrf = CSRFProtect(app)
BASE = "/srv/arquivos"


@app.route("/baixar")
@login_required
def baixar():
    # send_from_directory aplica safe_join ao nome do arquivo.
    return send_from_directory(BASE, request.args.get("arquivo"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    enviado = request.files["documento"]
    enviado.save(os.path.join(BASE, secure_filename(enviado.filename)))
    return jsonify(ok=True)


@app.route("/ler/<nome>")
@login_required
def ler(nome):
    # Canonicaliza e confina a base antes de abrir.
    destino = os.path.realpath(os.path.join(BASE, nome))
    if not destino.startswith(BASE + os.sep):
        abort(400)
    with open(destino) as arquivo:
        return jsonify(conteudo=arquivo.read())


@app.route("/miniatura/<nome>")
@login_required
def miniatura(nome):
    alvo = (Path(BASE) / nome).resolve()
    if not alvo.is_relative_to(BASE):
        abort(400)
    return jsonify(tamanho=len(alvo.read_bytes()))


@app.route("/pagina/<int:numero>")
@login_required
def pagina(numero):
    # Parametro convertido para inteiro nao carrega "../".
    return jsonify(Path(BASE, f"pagina-{int(numero)}.txt").read_text())
