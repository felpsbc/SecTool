"""Amostra vulneravel a Open Redirect (gabarito inline). Nao executar."""

from django.http import HttpResponseRedirect
from flask import Flask, redirect, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.route("/entrar/concluido")
def apos_login():
    destino = request.args.get("next") or "/"
    return redirect(destino)  # achado: CWE-601


@app.route("/sair")
def sair():
    # startswith("/") nao impede "//site-malicioso.com".
    volta = request.args.get("volta", "/")
    if volta.startswith("/"):
        return redirect(volta)  # achado: CWE-601
    return redirect("/")


def view_django(request_django):
    return HttpResponseRedirect(request.referrer)  # achado: CWE-601
