"""App Flask propositalmente vulneravel, para testar o AEGIS pelo site.

NAO USE EM PRODUCAO. Cada rota tem um defeito conhecido, anotado no
comentario; o resultado esperado da analise esta em ROTEIRO_DE_TESTE.md.
"""

import sqlite3

from flask import Flask, redirect, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "segredo-de-desenvolvimento-123"  # CWE-798


def conectar():
    return sqlite3.connect("loja.db")


@app.route("/produto")
def produto():
    # CWE-89: id da URL concatenado na query
    ident = request.args.get("id")
    cursor = conectar().cursor()
    cursor.execute("SELECT nome, preco FROM produtos WHERE id = " + ident)
    return str(cursor.fetchone())


@app.route("/busca")
def busca():
    # CWE-79: termo de busca devolvido como HTML sem escape
    termo = request.args.get("q", "")
    return "<h1>Resultados para " + termo + "</h1>"


@app.route("/sair")
def sair():
    # CWE-601: destino do redirect vem do usuario
    return redirect(request.args.get("proximo"))


@app.route("/download")
def download():
    # CWE-22: nome de arquivo do usuario vira caminho no disco
    nome = request.args.get("arquivo")
    return send_file("/srv/uploads/" + nome)


@app.route("/pedido/<int:pedido_id>")
def pedido(pedido_id):
    # CWE-639 (candidato): busca pelo id da URL sem checar o dono
    cursor = conectar().cursor()
    cursor.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,))
    return str(cursor.fetchone())


@app.route("/produto-seguro")
def produto_seguro():
    # Controle negativo: query parametrizada, nao deve gerar SQLi
    ident = request.args.get("id")
    cursor = conectar().cursor()
    cursor.execute("SELECT nome, preco FROM produtos WHERE id = ?", (ident,))
    return str(cursor.fetchone())
