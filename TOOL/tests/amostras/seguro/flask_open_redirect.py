"""Contraparte segura de Open Redirect. Nenhum achado de CWE-601 esperado."""

from urllib.parse import urlparse

from django.utils.http import url_has_allowed_host_and_scheme
from flask import Flask, redirect, request, url_for
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.route("/entrar/concluido")
def apos_login():
    destino = request.args.get("next")
    if destino and url_has_allowed_host_and_scheme(destino, allowed_hosts={"app.exemplo"}):
        return redirect(destino)
    return redirect(url_for("inicio"))


@app.route("/sair")
def sair():
    volta = request.args.get("volta", "/")
    if urlparse(volta).netloc:
        return redirect(url_for("inicio"))
    return redirect(volta)


@app.route("/perfil")
def perfil():
    # O dado vira parametro de uma URL interna, nao o destino.
    return redirect(url_for("ver_perfil", aba=request.args.get("aba")))
