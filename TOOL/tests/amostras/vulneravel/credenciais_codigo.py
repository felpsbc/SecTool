"""Amostra com credenciais fixas no codigo (gabarito inline). Nao executar.

Padrao tipico de codigo gerado por IA: segredo de desenvolvimento que vai
para producao, usuario de teste criado no proprio app, senha-mestra.
"""

import os
import smtplib

import psycopg2
import requests
from django.contrib.auth.models import User

SECRET_KEY = "dev-secret-nao-usar"  # achado: CWE-798
DATABASE_URL = "postgresql://app:Sup3rS3nh4@db.interno:5432/loja"  # achado: CWE-798
JWT_SECRET = os.getenv("JWT_SECRET", "troque-depois")  # achado: CWE-798
STRIPE_API_KEY = "sk_live_51HxExemploDeChave"  # achado: CWE-798

USUARIOS_DE_TESTE = [
    {"username": "teste", "password": "teste123"},  # achado: CWE-798
]


def conectar():
    return psycopg2.connect(host="db", user="app", password="postgres123")  # achado: CWE-798


def criar_admin():
    User.objects.create_superuser("admin", "admin@loja.com", "admin123")  # achado: CWE-798


def autenticar(usuario, senha):
    if usuario == "admin" and senha == "M4st3rK3y!":  # achado: CWE-798
        return True
    return verificar_no_banco(usuario, senha)


def enviar_relatorio(texto, remetente="relatorios@loja.com", smtp_senha="Relat0r10s"):  # achado: CWE-798
    servidor = smtplib.SMTP("smtp.loja.com", 587)
    servidor.login(remetente, "Relat0r10s")  # achado: CWE-798
    servidor.sendmail(remetente, ["diretoria@loja.com"], texto)


def consultar_parceiro():
    return requests.get("https://api.parceiro.com/v1/pedidos", auth=("loja", "p4rc3ir0"))  # achado: CWE-798


class Config:
    MAIL_PASSWORD = "senha-do-email"  # achado: CWE-798
