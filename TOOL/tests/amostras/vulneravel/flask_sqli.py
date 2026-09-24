"""Amostra Flask com SQL Injection proposital (gabarito inline).

Nao executar. Cada sink vulneravel carrega o marcador de gabarito na
sua propria linha; ver tests/conftest.py.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)  # achado: CWE-352


def conexao():
    return sqlite3.connect("loja.db")


@app.route("/usuario")
def buscar_usuario():
    ident = request.args["id"]
    cursor = conexao().cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = " + ident)  # achado: CWE-89, CWE-639
    return str(cursor.fetchall())


@app.route("/busca")
def buscar_produto():
    termo = request.args.get("q", "")
    cursor = conexao().cursor()
    cursor.execute(f"SELECT * FROM produtos WHERE nome LIKE '%{termo}%'")  # achado: CWE-89
    return str(cursor.fetchall())


@app.route("/pedido", methods=["POST"])
def registrar_pedido():
    dados = request.form
    cursor = conexao().cursor()
    consulta = "INSERT INTO pedidos (cliente, item) VALUES ('%s', '%s')" % (
        dados["cliente"],
        dados["item"],
    )
    cursor.execute(consulta)  # achado: CWE-89
    return "ok"


@app.route("/relatorio")
def relatorio():
    ordem = request.args["ordem"]
    cursor = conexao().cursor()
    cursor.executemany("SELECT * FROM vendas ORDER BY {}".format(ordem), [])  # achado: CWE-89
    return "ok"


@app.route("/perfil")
def perfil():
    ident = request.args["id"]
    cursor = conexao().cursor()
    cursor.execute(montar_consulta(ident))  # achado: CWE-89
    return "ok"


def montar_consulta(ident):
    return "SELECT * FROM usuarios WHERE id = " + ident


def executar_consulta(cursor, consulta):
    # O taint entra por parametro, vindo de outra funcao: o motor
    # intraprocedural nao ve a fonte daqui.
    cursor.execute(consulta)  # limitacao: CWE-89 fluxo interprocedural


@app.route("/legado")
def legado():
    cursor = conexao().cursor()
    executar_consulta(cursor, "SELECT * FROM logs WHERE ip = " + request.args["ip"])
    return "ok"
