"""Descoberta e parse de arquivos das linguagens suportadas via tree-sitter.

O tree-sitter e importado sob demanda: sem o extra `[linguagens]`, cada
arquivo vira `FalhaDeLeitura` com motivo "dependencia" e a varredura segue.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from owaspscan.analisador import (
    DIRETORIOS_IGNORADOS,
    LIMITE_TRECHO,
    FalhaDeLeitura,
    caminho_relativo,
    normalizar_trecho,
)

TAMANHO_MAXIMO = 1_000_000  # bytes; bundles gerados ficam de fora

# extensao -> linguagem
EXTENSOES: dict[str, str] = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".php": "php",
    ".html": "html",
    ".htm": "html",
}

# Codigo gerado/minificado: nao e o codigo que o projeto escreveu.
SUFIXOS_IGNORADOS: tuple[str, ...] = (".min.js", ".bundle.js", ".d.ts")

MENSAGEM_SEM_TREE_SITTER = (
    "analise desta linguagem requer o extra opcional: "
    'pip install -e ".[linguagens]"'
)


class DependenciaAusente(RuntimeError):
    """tree-sitter ou a gramatica da linguagem nao esta instalada."""


def linguagem_de(caminho: Path | str) -> str | None:
    nome = Path(caminho).name.lower()
    if nome.endswith(SUFIXOS_IGNORADOS):
        return None
    return EXTENSOES.get(Path(nome).suffix)


@lru_cache(maxsize=None)
def parser_para(linguagem: str):
    """Parser do tree-sitter para a linguagem, criado uma vez por processo."""
    try:
        from tree_sitter import Language, Parser

        if linguagem == "javascript":
            import tree_sitter_javascript as gramatica

            bruta = gramatica.language()
        elif linguagem in ("typescript", "tsx"):
            import tree_sitter_typescript as gramatica

            bruta = (
                gramatica.language_tsx()
                if linguagem == "tsx"
                else gramatica.language_typescript()
            )
        elif linguagem == "java":
            import tree_sitter_java as gramatica

            bruta = gramatica.language()
        elif linguagem == "php":
            import tree_sitter_php as gramatica

            bruta = gramatica.language_php()
        elif linguagem == "html":
            import tree_sitter_html as gramatica

            bruta = gramatica.language()
        else:
            raise DependenciaAusente(f"linguagem sem gramatica: {linguagem}")
    except ImportError as erro:
        raise DependenciaAusente(MENSAGEM_SEM_TREE_SITTER) from erro
    return Parser(Language(bruta))


def tree_sitter_disponivel() -> bool:
    try:
        parser_para("javascript")
    except DependenciaAusente:
        return False
    return True


@dataclass(frozen=True)
class ArquivoPoliglota:
    """Um arquivo de outra linguagem parseado, com a origem preservada.

    `linha_inicial` desloca as linhas quando o codigo foi extraido de outro
    arquivo (um <script> dentro de HTML comeca no meio da pagina).
    """

    arquivo: str
    linguagem: str
    fonte: bytes
    raiz: object  # tree_sitter.Node
    linha_inicial: int = 1

    def linha_de(self, no) -> int:
        return no.start_point[0] + self.linha_inicial

    def trecho_de(self, no, limite: int = LIMITE_TRECHO) -> str:
        texto = self.fonte[no.start_byte : no.end_byte].decode("utf-8", "replace")
        return normalizar_trecho(texto, limite)


def analisar_texto_poliglota(
    fonte: str | bytes, linguagem: str, arquivo: str = "<memoria>", linha_inicial: int = 1
) -> ArquivoPoliglota:
    """Parseia codigo em memoria. Levanta DependenciaAusente sem tree-sitter.

    O tree-sitter tolera erro de sintaxe (gera nos ERROR e segue), entao,
    diferente do nucleo Python, arquivo com sintaxe quebrada ainda e analisado
    no que for parseavel.
    """
    dados = fonte.encode("utf-8") if isinstance(fonte, str) else fonte
    arvore = parser_para(linguagem).parse(dados)
    return ArquivoPoliglota(
        arquivo=arquivo,
        linguagem=linguagem,
        fonte=dados,
        raiz=arvore.root_node,
        linha_inicial=linha_inicial,
    )


def descobrir_arquivos_poliglotas(raiz: Path) -> list[Path]:
    """Arquivos das linguagens suportadas sob a raiz, em ordem estavel."""
    raiz = Path(raiz)
    if raiz.is_file():
        return [raiz] if linguagem_de(raiz) else []
    encontrados: list[Path] = []
    for caminho in sorted(raiz.rglob("*")):
        if not caminho.is_file() or linguagem_de(caminho) is None:
            continue
        partes = caminho.relative_to(raiz).parts[:-1]
        if any(parte in DIRETORIOS_IGNORADOS for parte in partes):
            continue
        encontrados.append(caminho)
    return encontrados


def analisar_arquivo_poliglota(
    caminho: Path, raiz: Path | None = None
) -> ArquivoPoliglota | FalhaDeLeitura:
    """Le e parseia um arquivo. Devolve a falha em vez de levantar excecao."""
    caminho = Path(caminho)
    base = Path(raiz) if raiz is not None else caminho.parent
    exibicao = caminho_relativo(caminho, base)
    linguagem = linguagem_de(caminho)
    if linguagem is None:
        return FalhaDeLeitura(
            arquivo=exibicao, motivo="io", mensagem="extensao nao suportada"
        )
    try:
        if caminho.stat().st_size > TAMANHO_MAXIMO:
            return FalhaDeLeitura(
                arquivo=exibicao,
                motivo="io",
                mensagem=f"arquivo maior que {TAMANHO_MAXIMO} bytes (provavelmente gerado)",
            )
        dados = caminho.read_bytes()
    except OSError as erro:
        return FalhaDeLeitura(arquivo=exibicao, motivo="io", mensagem=str(erro))
    try:
        dados.decode("utf-8")
    except UnicodeDecodeError as erro:
        return FalhaDeLeitura(arquivo=exibicao, motivo="codificacao", mensagem=str(erro))
    try:
        return analisar_texto_poliglota(dados, linguagem, exibicao)
    except DependenciaAusente as erro:
        return FalhaDeLeitura(arquivo=exibicao, motivo="dependencia", mensagem=str(erro))


def analisar_diretorio_poliglota(
    raiz: Path,
) -> tuple[list[ArquivoPoliglota], list[FalhaDeLeitura]]:
    raiz = Path(raiz)
    base = raiz if raiz.is_dir() else raiz.parent
    analisados: list[ArquivoPoliglota] = []
    falhas: list[FalhaDeLeitura] = []
    for caminho in descobrir_arquivos_poliglotas(raiz):
        resultado = analisar_arquivo_poliglota(caminho, base)
        if isinstance(resultado, FalhaDeLeitura):
            falhas.append(resultado)
        else:
            analisados.append(resultado)
    return analisados, falhas
