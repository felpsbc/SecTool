"""Contraparte segura da amostra de XSS. Nenhum achado esperado aqui."""

from flask import Flask, jsonify, redirect, render_template, request
from markupsafe import escape

app = Flask(__name__)  # achado: CWE-352


@app.route("/ola")
def ola():
    # Auto-escape do Jinja2 cuida do dado passado como contexto.
    return render_template("ola.html", nome=request.args["nome"])


@app.route("/perfil", methods=["POST"])
def perfil():  # achado: CWE-862
    bio = escape(request.form["bio"])
    return "<div class='bio'>" + bio + "</div>"


@app.route("/api/busca")
def api_busca():
    # Resposta JSON nao e interpretada como HTML pelo navegador.
    return jsonify(termo=request.args["q"])


@app.route("/estatico")
def estatico():
    return "<h1>Bem-vindo</h1>"


@app.route("/ir")
def ir():
    # Nao e XSS: redirect nao devolve HTML. E, porem, open redirect
    # (CWE-601): a amostra e segura para a CWE que nomeia, nao para todas.
    return redirect(request.args["destino"])  # achado: CWE-601


@app.route("/contador")
def contador():
    total = int(request.args["n"])
    return f"<p>{total}</p>"
