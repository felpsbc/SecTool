"""Fixture congelado da Fase 1. Nao editar sem ajustar test_analisador.py."""

TABELA = "usuarios"


def busca(cursor, id_usuario):
    cursor.execute("SELECT * FROM usuarios WHERE id = " + id_usuario)
    return cursor.fetchone()


def busca_multilinha(cursor, id_usuario):
    cursor.execute(
        "SELECT * FROM usuarios WHERE id = "
        + id_usuario
    )
    return cursor.fetchall()
