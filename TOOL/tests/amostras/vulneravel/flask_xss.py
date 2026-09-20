"""Amostra Flask com XSS refletido proposital (gabarito inline).

Nao executar. Cada sink vulneravel carrega o marcador de gabarito na sua
propria linha; ver tests/conftest.py.
"""

from flask import Flask, make_response, render_template_string, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/ola")
def ola():
    nome = request.args["nome"]
    return f"<h1>Ola, {nome}</h1>"  # achado: CWE-79


@app.route("/perfil", methods=["POST"])
def perfil():
    bio = request.form["bio"]
    return render_template_string("<div class='bio'>" + bio + "</div>")  # achado: CWE-79


@app.route("/comentario")
def comentario():
    texto = request.args.get("texto", "")
    return Markup("<p>" + texto + "</p>")  # achado: CWE-79


@app.route("/busca")
def busca():
    termo = request.args["q"]
    return make_response("<p>Resultados para " + termo + "</p>")  # achado: CWE-79


def renderizar_bloco(texto):
    # Bypass explicito do auto-escape fora de uma view: continua sendo achado.
    return Markup("<section>" + texto + "</section>")


@app.route("/painel")
def painel():
    rotulo = request.args["rotulo"]
    return Markup("<span>" + rotulo + "</span>")  # achado: CWE-79
