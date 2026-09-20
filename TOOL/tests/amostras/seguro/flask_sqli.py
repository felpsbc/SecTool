"""Contraparte segura da amostra de SQLi: segura para CWE-89.

Nenhum achado de SQL Injection e esperado aqui. As linhas marcadas com
CWE-639 sao candidatos a IDOR legitimos: parametrizar a query impede
alterar sua estrutura, mas nao impede pedir o registro de outro usuario.
"""

import sqlite3
import uuid

from flask import Flask, request

app = Flask(__name__)


def conexao():
    return sqlite3.connect("loja.db")


@app.route("/usuario")
def buscar_usuario():
    ident = request.args["id"]
    cursor = conexao().cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = ?", (ident,))  # achado: CWE-639
    return str(cursor.fetchall())


@app.route("/usuario-nomeado")
def buscar_usuario_nomeado():
    cursor = conexao().cursor()
    consulta = "SELECT * FROM usuarios WHERE id = :id"
    cursor.execute(consulta, {"id": request.args["id"]})  # achado: CWE-639
    return str(cursor.fetchall())


@app.route("/todos")
def listar_todos():
    cursor = conexao().cursor()
    cursor.execute("SELECT * FROM usuarios ORDER BY nome")
    return str(cursor.fetchall())


@app.route("/ativos")
def listar_ativos():
    status = "ativo"
    cursor = conexao().cursor()
    cursor.execute("SELECT * FROM usuarios WHERE status = '" + status + "'")
    return str(cursor.fetchall())


@app.route("/lote", methods=["POST"])
def inserir_lote():
    cursor = conexao().cursor()
    cursor.executemany(
        "INSERT INTO itens (nome) VALUES (?)",
        [(nome,) for nome in request.form.getlist("nomes")],
    )
    return "ok"


@app.route("/usuario-inteiro")
def buscar_usuario_inteiro():
    ident = int(request.args["id"])
    cursor = conexao().cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = " + str(ident))  # achado: CWE-639
    return str(cursor.fetchall())


@app.route("/pedido-uuid")
def buscar_pedido_uuid():
    referencia = uuid.UUID(request.args["ref"])
    cursor = conexao().cursor()
    cursor.execute(f"SELECT * FROM pedidos WHERE ref = '{referencia}'")
    return str(cursor.fetchall())
