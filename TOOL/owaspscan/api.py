"""Camada HTTP: expoe a varredura para um site.

    python -m owaspscan.api                 # http://127.0.0.1:8000/docs

POST /analisar aceita dois formatos, para o site usar o que for mais facil:

  application/json      {"codigo": "...", "nome": "app.py",
                         "arquivos": [{"nome": "views.py", "conteudo": "..."}]}
  multipart/form-data   campos `codigo`, `nome` e `arquivos` (upload direto
                        de <input type="file" multiple>)

O conteudo e gravado numa pasta temporaria, analisado por `executar()` e
devolvido como `para_dict()` — o mesmo JSON de `python -m owaspscan --json`.

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

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError
from starlette.datastructures import UploadFile

from owaspscan.configuracao import formato_de
from owaspscan.poliglota.fonte import linguagem_de
from owaspscan.relatorio import para_dict
from owaspscan.varredura import VERSAO, executar

MAXIMO_DE_ARQUIVOS = 50
TAMANHO_MAXIMO_POR_ARQUIVO = 1_000_000  # bytes, mesmo teto dos arquivos de configuracao
NOME_DO_CODIGO_COLADO = "codigo.py"
RAIZ_EXIBIDA = "envio"  # substitui o caminho temporario, que nao interessa ao usuario

# Origens do site autorizadas a chamar a API, separadas por virgula.
ORIGENS = [o.strip() for o in os.environ.get("OWASPSCAN_ORIGENS", "*").split(",") if o.strip()]


class ArquivoEnviado(BaseModel):
    nome: str = Field(description="nome do arquivo, ex. views.py ou .env")
    conteudo: str = Field(description="texto do arquivo")


class Envio(BaseModel):
    """Corpo JSON de POST /analisar."""

    codigo: str | None = Field(
        None, description="codigo colado no site; a linguagem vem da extensao de `nome`"
    )
    nome: str = Field(NOME_DO_CODIGO_COLADO, description="nome exibido para o codigo colado")
    arquivos: list[ArquivoEnviado] = Field(default_factory=list)


app = FastAPI(
    title="OWASP-Scan",
    version=VERSAO,
    description=(
        "Analise estatica (AST + taint tracking) de Python, JavaScript/TypeScript, "
        "Java, PHP e HTML contra o OWASP Top 10:2021."
    ),
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
    if not base.endswith(".py") and formato_de(Path(base)) is None and linguagem_de(base) is None:
        raise HTTPException(
            400,
            f"tipo de arquivo nao suportado: {base!r} "
            "(aceitos: .py, .js/.ts/.jsx/.tsx, .java, .php, .html e configuracao "
            ".env/.yaml/.json/.ini/.toml/.properties)",
        )
    return base


def _texto(valor: str | bytes) -> bytes:
    return valor.encode("utf-8") if isinstance(valor, str) else valor


def montar_envios(
    codigo: str | None, nome: str, arquivos: list[tuple[str | None, str | bytes]]
) -> dict[str, bytes]:
    """Valida o envio (qualquer formato) e devolve {nome_seguro: conteudo}."""
    if len(arquivos) > MAXIMO_DE_ARQUIVOS:
        raise HTTPException(413, f"no maximo {MAXIMO_DE_ARQUIVOS} arquivos por envio")

    pares = [(nome, codigo)] if codigo is not None and codigo.strip() else []
    pares += arquivos

    envios: dict[str, bytes] = {}
    for nome_enviado, conteudo in pares:
        nome_do_arquivo = nome_seguro(nome_enviado)
        if nome_do_arquivo in envios:
            raise HTTPException(400, f"arquivo repetido no envio: {nome_do_arquivo!r}")
        dados = _texto(conteudo)
        if len(dados) > TAMANHO_MAXIMO_POR_ARQUIVO:
            raise HTTPException(413, f"{nome_do_arquivo} excede {TAMANHO_MAXIMO_POR_ARQUIVO} bytes")
        envios[nome_do_arquivo] = dados

    if not envios:
        raise HTTPException(400, "envie codigo no campo 'codigo' ou arquivos no campo 'arquivos'")
    return envios


def varrer(envios: dict[str, bytes]) -> dict[str, object]:
    """Grava o envio numa pasta temporaria, roda executar() e devolve para_dict()."""
    with tempfile.TemporaryDirectory(prefix="owaspscan-") as pasta:
        raiz = Path(pasta)
        for nome_do_arquivo, conteudo in envios.items():
            (raiz / nome_do_arquivo).write_bytes(conteudo)
        varredura = executar(raiz)
    return para_dict(replace(varredura, raiz=RAIZ_EXIBIDA))


async def _envios_de_json(request: Request) -> dict[str, bytes]:
    try:
        envio = Envio.model_validate(await request.json())
    except ValueError as erro:  # JSON malformado ou fora do esquema
        detalhe = erro.errors(include_url=False) if isinstance(erro, ValidationError) else str(erro)
        raise HTTPException(422, detalhe) from erro
    return montar_envios(
        envio.codigo, envio.nome, [(a.nome, a.conteudo) for a in envio.arquivos]
    )


async def _envios_de_formulario(request: Request) -> dict[str, bytes]:
    # Tetos do Starlette um pouco acima dos nossos, para o erro sair daqui
    # (413 com mensagem clara) e nao do parser (400 generico).
    formulario = await request.form(
        max_files=MAXIMO_DE_ARQUIVOS + 1, max_part_size=2 * TAMANHO_MAXIMO_POR_ARQUIVO
    )
    codigo = formulario.get("codigo")
    arquivos = []
    for item in formulario.getlist("arquivos"):
        if not isinstance(item, UploadFile):
            raise HTTPException(400, "o campo 'arquivos' deve conter arquivos, nao texto")
        # le um byte a mais que o limite para detectar excesso sem ler tudo
        arquivos.append((item.filename, await item.read(TAMANHO_MAXIMO_POR_ARQUIVO + 1)))
    return montar_envios(
        codigo if isinstance(codigo, str) else None,
        str(formulario.get("nome") or NOME_DO_CODIGO_COLADO),
        arquivos,
    )


@app.get("/saude")
def saude() -> dict[str, str]:
    return {"status": "ok", "versao": VERSAO}


@app.post(
    "/analisar",
    summary="Analisa codigo colado e/ou arquivos enviados",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": Envio.model_json_schema(ref_template="#/components/schemas/{model}")},
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "codigo": {"type": "string"},
                            "nome": {"type": "string", "default": NOME_DO_CODIGO_COLADO},
                            "arquivos": {"type": "array", "items": {"type": "string", "format": "binary"}},
                        },
                    }
                },
            },
        }
    },
)
async def analisar(request: Request) -> dict[str, object]:
    tipo = request.headers.get("content-type", "")
    if tipo.startswith("application/json"):
        envios = await _envios_de_json(request)
    elif tipo.startswith(("multipart/form-data", "application/x-www-form-urlencoded")):
        envios = await _envios_de_formulario(request)
    else:
        raise HTTPException(415, "use Content-Type application/json ou multipart/form-data")
    # a varredura e CPU-bound: roda fora do event loop
    return await run_in_threadpool(varrer, envios)


# O schema JSON do corpo referencia ArquivoEnviado; registra-o no OpenAPI.
_openapi_original = app.openapi


def _openapi() -> dict:
    if app.openapi_schema is None:
        esquema = _openapi_original()
        componentes = esquema.setdefault("components", {}).setdefault("schemas", {})
        componentes.update(Envio.model_json_schema(ref_template="#/components/schemas/{model}").get("$defs", {}))
    return app.openapi_schema


app.openapi = _openapi


def main() -> None:
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("OWASPSCAN_HOST", "127.0.0.1"),
        port=int(os.environ.get("OWASPSCAN_PORTA", "8000")),
    )


if __name__ == "__main__":
    main()
