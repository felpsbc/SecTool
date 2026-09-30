"""Camada HTTP: expoe a varredura para um site.

    uvicorn owaspscan.api:app --reload

POST /analisar recebe multipart/form-data com codigo colado (`codigo`),
arquivos enviados (`arquivos`) ou os dois. O conteudo e gravado numa pasta
temporaria, analisado por `executar()` e devolvido como `para_dict()`.

O codigo do usuario nunca e executado: o motor so parseia a AST. Mesmo
assim a entrada e hostil por definicao, entao os nomes de arquivo sao
reduzidos ao nome-base (sem path traversal) e ha limite de tamanho.

Fora do nucleo de proposito: FastAPI e dependencia opcional (extra `api`),
o scanner continua rodando so com a stdlib.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from owaspscan.configuracao import formato_de
from owaspscan.relatorio import para_dict
from owaspscan.varredura import VERSAO, executar

MAXIMO_DE_ARQUIVOS = 50
TAMANHO_MAXIMO_POR_ARQUIVO = 1_000_000  # bytes, mesmo teto dos arquivos de configuracao
NOME_DO_CODIGO_COLADO = "codigo.py"
RAIZ_EXIBIDA = "envio"  # substitui o caminho temporario, que nao interessa ao usuario

# Origens do site autorizadas a chamar a API, separadas por virgula.
ORIGENS = [o.strip() for o in os.environ.get("OWASPSCAN_ORIGENS", "*").split(",") if o.strip()]

app = FastAPI(
    title="OWASP-Scan",
    version=VERSAO,
    description="Analise estatica (AST + taint tracking) de codigo Python contra o OWASP Top 10:2021.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGENS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def nome_seguro(nome: str | None) -> str:
    """Nome-base do arquivo enviado; rejeita o que nao da para analisar.

    Navegadores costumam mandar so o nome, mas nada impede um cliente de
    enviar "../../etc/passwd" ou "C:\\x\\app.py". Tudo antes da ultima
    barra (de qualquer sistema) e descartado.
    """
    base = PureWindowsPath(PurePosixPath(nome or "").name).name
    if base in {"", ".", ".."}:
        raise HTTPException(400, f"nome de arquivo invalido: {nome!r}")
    if not base.endswith(".py") and formato_de(Path(base)) is None:
        raise HTTPException(
            400,
            f"tipo de arquivo nao suportado: {base!r} "
            "(aceitos: .py e configuracao .env/.yaml/.json/.ini/.toml/.properties)",
        )
    return base


def _limitar(nome: str, conteudo: bytes) -> bytes:
    if len(conteudo) > TAMANHO_MAXIMO_POR_ARQUIVO:
        raise HTTPException(413, f"{nome} excede {TAMANHO_MAXIMO_POR_ARQUIVO} bytes")
    return conteudo


@app.get("/saude")
def saude() -> dict[str, str]:
    return {"status": "ok", "versao": VERSAO}


@app.post("/analisar")
def analisar(
    codigo: str | None = Form(None, description="codigo Python colado no site"),
    nome: str = Form(NOME_DO_CODIGO_COLADO, description="nome exibido para o codigo colado"),
    arquivos: list[UploadFile] = File(default_factory=list, description="arquivos .py ou de configuracao"),
) -> dict[str, object]:
    # `def` sincrono de proposito: a varredura e CPU-bound e o FastAPI roda
    # rotas sincronas num pool de threads, sem travar o event loop.
    envios: dict[str, bytes] = {}

    if codigo is not None and codigo.strip():
        nome_do_codigo = nome_seguro(nome)
        envios[nome_do_codigo] = _limitar(nome_do_codigo, codigo.encode("utf-8"))

    if len(arquivos) > MAXIMO_DE_ARQUIVOS:
        raise HTTPException(413, f"no maximo {MAXIMO_DE_ARQUIVOS} arquivos por envio")
    for arquivo in arquivos:
        nome_do_arquivo = nome_seguro(arquivo.filename)
        if nome_do_arquivo in envios:
            raise HTTPException(400, f"arquivo repetido no envio: {nome_do_arquivo!r}")
        # le um byte a mais que o limite para detectar excesso sem ler tudo
        conteudo = arquivo.file.read(TAMANHO_MAXIMO_POR_ARQUIVO + 1)
        envios[nome_do_arquivo] = _limitar(nome_do_arquivo, conteudo)

    if not envios:
        raise HTTPException(400, "envie codigo no campo 'codigo' ou arquivos no campo 'arquivos'")

    with tempfile.TemporaryDirectory(prefix="owaspscan-") as pasta:
        raiz = Path(pasta)
        for nome_do_arquivo, conteudo in envios.items():
            (raiz / nome_do_arquivo).write_bytes(conteudo)
        varredura = executar(raiz)

    return para_dict(replace(varredura, raiz=RAIZ_EXIBIDA))
