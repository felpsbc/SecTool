"""Camada AST: descoberta de arquivos, parse resiliente e localizacao de nos.

Esta camada nao sabe nada sobre vulnerabilidades. Ela entrega arvores
sintaticas com a informacao de origem (caminho relativo, linha, trecho) que
os detectores usam para montar achados.
"""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass
from pathlib import Path

# Diretorios que nunca contem codigo-fonte do projeto analisado.
DIRETORIOS_IGNORADOS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        "build",
        "dist",
        "node_modules",
        "site-packages",
    }
)

LIMITE_TRECHO = 120


@dataclass(frozen=True)
class FalhaDeLeitura:
    """Arquivo que nao pode ser analisado. Registrado, nunca fatal."""

    arquivo: str
    motivo: str  # "sintaxe" | "codificacao" | "io"
    mensagem: str
    linha: int | None = None


@dataclass(frozen=True)
class ArquivoAnalisado:
    """Um modulo Python parseado, com sua origem preservada."""

    arquivo: str  # caminho relativo a raiz analisada
    caminho: Path  # caminho real em disco, para uso interno
    fonte: str
    arvore: ast.Module

    def linha_de(self, no: ast.AST) -> int:
        """Linha 1-indexada do no; 1 quando o no nao carrega posicao."""
        return getattr(no, "lineno", 1)

    def trecho_de(self, no: ast.AST, limite: int = LIMITE_TRECHO) -> str:
        """Codigo-fonte do no, normalizado para uma unica linha.

        Cai para a linha fisica do no quando o segmento exato nao esta
        disponivel (nos sinteticos ou sem posicao de fim).
        """
        segmento = ast.get_source_segment(self.fonte, no)
        if segmento is None:
            segmento = self._linha_fisica(no)
        return normalizar_trecho(segmento, limite)

    def _linha_fisica(self, no: ast.AST) -> str:
        numero = getattr(no, "lineno", None)
        if numero is None:
            return ""
        linhas = self.fonte.splitlines()
        if 1 <= numero <= len(linhas):
            return linhas[numero - 1]
        return ""


def normalizar_trecho(texto: str, limite: int = LIMITE_TRECHO) -> str:
    """Colapsa quebras de linha e espacos repetidos, truncando com reticencias."""
    uma_linha = " ".join(texto.split())
    if len(uma_linha) <= limite:
        return uma_linha
    return uma_linha[: limite - 3].rstrip() + "..."


def caminho_relativo(caminho: Path, raiz: Path) -> str:
    """Caminho de exibicao, relativo a raiz analisada, com barras POSIX."""
    try:
        return caminho.resolve().relative_to(raiz.resolve()).as_posix()
    except ValueError:
        return caminho.name


def descobrir_arquivos(raiz: Path) -> list[Path]:
    """Lista arquivos .py sob a raiz, em ordem estavel, pulando diretorios de build."""
    raiz = Path(raiz)
    if raiz.is_file():
        return [raiz] if raiz.suffix == ".py" else []
    encontrados: list[Path] = []
    for caminho in sorted(raiz.rglob("*.py")):
        partes = caminho.relative_to(raiz).parts[:-1]
        if any(parte in DIRETORIOS_IGNORADOS for parte in partes):
            continue
        encontrados.append(caminho)
    return encontrados


def analisar_arquivo(
    caminho: Path, raiz: Path | None = None
) -> ArquivoAnalisado | FalhaDeLeitura:
    """Le e parseia um arquivo. Devolve a falha em vez de levantar excecao."""
    caminho = Path(caminho)
    base = Path(raiz) if raiz is not None else caminho.parent
    exibicao = caminho_relativo(caminho, base)

    try:
        with tokenize.open(caminho) as arquivo:
            fonte = arquivo.read()
    except (UnicodeDecodeError, UnicodeError) as erro:
        return FalhaDeLeitura(
            arquivo=exibicao, motivo="codificacao", mensagem=str(erro)
        )
    except SyntaxError as erro:  # cookie de encoding invalido
        return FalhaDeLeitura(
            arquivo=exibicao,
            motivo="codificacao",
            mensagem=erro.msg,
            linha=erro.lineno,
        )
    except OSError as erro:
        return FalhaDeLeitura(arquivo=exibicao, motivo="io", mensagem=str(erro))

    try:
        arvore = ast.parse(fonte, filename=str(caminho))
    except SyntaxError as erro:
        return FalhaDeLeitura(
            arquivo=exibicao,
            motivo="sintaxe",
            mensagem=erro.msg,
            linha=erro.lineno,
        )
    except ValueError as erro:  # fonte com byte nulo, por exemplo
        return FalhaDeLeitura(arquivo=exibicao, motivo="sintaxe", mensagem=str(erro))

    return ArquivoAnalisado(
        arquivo=exibicao, caminho=caminho, fonte=fonte, arvore=arvore
    )


def analisar_diretorio(
    raiz: Path,
) -> tuple[list[ArquivoAnalisado], list[FalhaDeLeitura]]:
    """Analisa todos os .py sob a raiz, separando sucessos de falhas."""
    raiz = Path(raiz)
    base = raiz if raiz.is_dir() else raiz.parent
    analisados: list[ArquivoAnalisado] = []
    falhas: list[FalhaDeLeitura] = []
    for caminho in descobrir_arquivos(raiz):
        resultado = analisar_arquivo(caminho, base)
        if isinstance(resultado, FalhaDeLeitura):
            falhas.append(resultado)
        else:
            analisados.append(resultado)
    return analisados, falhas


def analisar_texto(
    fonte: str, arquivo: str = "<memoria>"
) -> ArquivoAnalisado | FalhaDeLeitura:
    """Parseia codigo vindo de string. Usado em testes e em analise pontual."""
    try:
        arvore = ast.parse(fonte, filename=arquivo)
    except SyntaxError as erro:
        return FalhaDeLeitura(
            arquivo=arquivo, motivo="sintaxe", mensagem=erro.msg, linha=erro.lineno
        )
    return ArquivoAnalisado(
        arquivo=arquivo, caminho=Path(arquivo), fonte=fonte, arvore=arvore
    )
