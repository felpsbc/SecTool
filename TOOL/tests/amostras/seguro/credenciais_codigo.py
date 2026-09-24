"""Contraparte segura: segredos vindos do ambiente. Nenhum achado de CWE-798.

Exemplo de conexao documentado: postgresql://usuario:senha@host/banco
"""

import os

import psycopg2
import requests

SECRET_KEY = os.environ["SECRET_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")

# Metadados sobre credenciais, nao credenciais.
PASSWORD_MIN_LENGTH = 12
TOKEN_URL = "https://auth.loja.com/oauth/token"
TOKEN_TYPE = "Bearer"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher"]
SENHA_ENV = "DB_PASSWORD"
AUTH_PASSWORD_VALIDATORS = [{"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"}]
MENSAGEM_SENHA = "A senha deve ter ao menos 12 caracteres"
SEGREDO_PATH = "/run/secrets/app"


def conectar():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


def consultar_parceiro():
    auth = (os.environ["PARCEIRO_USUARIO"], os.environ["PARCEIRO_SENHA"])
    return requests.get("https://api.parceiro.com/v1/pedidos", auth=auth)


def formulario():
    # Placeholders de interface nao sao segredo.
    return {"password": "", "api_key": "<sua-chave-aqui>", "token": "${TOKEN}"}


def tipo_de_campo(campo):
    return campo.tipo == "password"
