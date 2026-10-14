"""Interface de linha de comando.

    python -m owaspscan caminho/ [--json]

Codigos de saida:
    0  nenhum achado de severidade alta
    1  ha pelo menos um achado de severidade alta
    2  erro de uso (caminho inexistente, por exemplo)

Candidatos heuristicos (confianca baixa) nao alteram o codigo de saida:
nao seria honesto quebrar um build com base em suposicao.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from owaspscan.relatorio import formatar_texto, para_dict
from owaspscan.varredura import VERSAO, executar

CODIGO_OK = 0
CODIGO_ACHADO_ALTO = 1
CODIGO_ERRO_DE_USO = 2


def montar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owasp-scan",
        description=(
            "Analisa codigo Python (Flask/Django), JavaScript/TypeScript, Java, PHP, "
            "HTML e arquivos de configuracao em "
            "busca de vulnerabilidades do OWASP Top 10:2021 — injecao (SQLi, "
            "XSS), controle de acesso (IDOR, path traversal, open redirect, "
            "CSRF, rota sem autorizacao), XXE, falhas de autenticacao e "
            "credenciais fixas — via AST e taint tracking."
        ),
    )
    parser.add_argument(
        "caminho",
        help="arquivo (.py, .js, .ts, .java, .php, .html, configuracao) ou diretorio a analisar",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="imprime o relatorio JSON no stdout (o resumo em texto vai para stderr)",
    )
    parser.add_argument("--versao", action="version", version=f"owasp-scan {VERSAO}")
    return parser


def main(argv: list[str] | None = None) -> int:
    argumentos = montar_parser().parse_args(argv)
    raiz = Path(argumentos.caminho)

    if not raiz.exists():
        print(f"erro: caminho nao encontrado: {raiz}", file=sys.stderr)
        return CODIGO_ERRO_DE_USO

    varredura = executar(raiz)
    texto = formatar_texto(varredura)

    if argumentos.json:
        # JSON limpo no stdout para encadear com jq; texto no stderr para
        # o resumo continuar visivel no terminal.
        print(texto, file=sys.stderr)
        print(json.dumps(para_dict(varredura), ensure_ascii=False, indent=2))
    else:
        print(texto)

    return CODIGO_ACHADO_ALTO if varredura.tem_severidade_alta else CODIGO_OK


if __name__ == "__main__":
    raise SystemExit(main())
