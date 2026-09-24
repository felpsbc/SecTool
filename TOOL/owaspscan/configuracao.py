"""Leitura de arquivos de configuracao nao-Python, para busca de credenciais.

Excecao declarada ao principio "somente AST": `.env`, YAML, JSON, INI e
afins nao sao Python. Cada formato e lido pela sua propria gramatica:

- JSON: `json` da stdlib (parser completo);
- `.env`, `.properties`, INI/CFG/CONF, TOML: formatos orientados a linha
  `chave = valor` / `chave: valor`, lidos linha a linha;
- YAML: nao ha parser na stdlib e o nucleo nao tem dependencias. Lemos
  pares `chave: valor` e itens `- CHAVE=valor` (lista `environment` do
  docker-compose). Limitacao: escalares de bloco (`|`, `>`), multi-linha
  e ancoras nao sao interpretados — valores assim sao ignorados.

A saida e uniforme: pares (chave, valor, linha) que o detector de
credenciais avalia com as mesmas regras usadas no codigo Python.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from owaspscan.analisador import DIRETORIOS_IGNORADOS, FalhaDeLeitura, caminho_relativo

TAMANHO_MAXIMO = 1_000_000  # bytes; lockfiles e dumps gigantes ficam de fora

EXTENSOES: dict[str, str] = {
    ".env": "env",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
    ".properties": "properties",
    ".toml": "toml",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
}

ARQUIVOS_IGNORADOS: frozenset[str] = frozenset(
    {"package-lock.json", "composer.lock", "yarn.lock", "poetry.lock", "Pipfile.lock", "tsconfig.json"}
)

# Marcadores de arquivo-modelo: valores ali sao, por intencao, ficticios.
MARCADORES_DE_EXEMPLO: tuple[str, ...] = (".example", ".sample", ".template", ".dist", "exemplo")


@dataclass(frozen=True)
class EntradaDeConfiguracao:
    """Um par chave/valor lido de um arquivo de configuracao."""

    chave: str
    valor: str
    linha: int
    texto: str  # linha fisica, para o trecho do relatorio


@dataclass(frozen=True)
class ArquivoDeConfiguracao:
    arquivo: str  # caminho relativo de exibicao
    formato: str
    entradas: tuple[EntradaDeConfiguracao, ...]

    @property
    def e_exemplo(self) -> bool:
        nome = self.arquivo.rsplit("/", 1)[-1].lower()
        return any(marcador in nome for marcador in MARCADORES_DE_EXEMPLO)


def formato_de(caminho: Path) -> str | None:
    """Formato do arquivo pelo nome, ou None se nao for configuracao."""
    nome = caminho.name
    if nome in ARQUIVOS_IGNORADOS:
        return None
    if nome == ".env" or nome.startswith(".env."):
        return "env"
    return EXTENSOES.get(caminho.suffix.lower())


def descobrir_configuracoes(raiz: Path) -> list[Path]:
    raiz = Path(raiz)
    if raiz.is_file():
        return [raiz] if formato_de(raiz) else []
    encontrados: list[Path] = []
    for caminho in sorted(raiz.rglob("*")):
        if not caminho.is_file() or formato_de(caminho) is None:
            continue
        partes = caminho.relative_to(raiz).parts[:-1]
        if any(parte in DIRETORIOS_IGNORADOS for parte in partes):
            continue
        encontrados.append(caminho)
    return encontrados


# --- Parsers ----------------------------------------------------------------


def _tirar_aspas(valor: str) -> tuple[str, bool]:
    """Remove aspas envolventes. Devolve (valor, estava_entre_aspas)."""
    valor = valor.strip()
    for aspa in ('"', "'"):
        if valor.startswith(aspa):
            fim = valor.find(aspa, 1)
            if fim > 0:
                return valor[1:fim], True
    return valor, False


def _sem_comentario(valor: str) -> str:
    """Corta comentario em linha (` #` ou ` ;`) de valor sem aspas."""
    for marcador in (" #", "\t#", " ;"):
        posicao = valor.find(marcador)
        if posicao >= 0:
            valor = valor[:posicao]
    return valor.strip()


def _valor(bruto: str, exige_aspas: bool = False) -> str | None:
    valor, entre_aspas = _tirar_aspas(bruto)
    if entre_aspas:
        return valor
    if exige_aspas:
        return None  # TOML: sem aspas e numero, booleano, data ou tabela
    return _sem_comentario(valor)


def ler_linhas_chave_valor(texto: str, formato: str) -> list[EntradaDeConfiguracao]:
    """Formatos de linha: .env, .properties, INI/CFG/CONF, TOML."""
    entradas: list[EntradaDeConfiguracao] = []
    comentarios = ("#", ";", "!") if formato in {"ini", "properties"} else ("#",)
    for numero, linha in enumerate(texto.splitlines(), start=1):
        conteudo = linha.strip()
        if not conteudo or conteudo.startswith(comentarios) or conteudo.startswith("["):
            continue
        if conteudo.startswith("export "):
            conteudo = conteudo[len("export "):]
        separadores = ("=", ":") if formato in {"properties", "ini"} else ("=",)
        posicoes = [conteudo.find(s) for s in separadores if conteudo.find(s) > 0]
        if not posicoes:
            continue
        corte = min(posicoes)
        chave = conteudo[:corte].strip().strip('"').strip("'")
        valor = _valor(conteudo[corte + 1:], exige_aspas=formato == "toml")
        if chave and valor is not None:
            entradas.append(EntradaDeConfiguracao(chave, valor, numero, linha))
    return entradas


def ler_yaml(texto: str) -> list[EntradaDeConfiguracao]:
    """Pares `chave: valor` e itens `- CHAVE=valor` / `- chave: valor`."""
    entradas: list[EntradaDeConfiguracao] = []
    for numero, linha in enumerate(texto.splitlines(), start=1):
        conteudo = linha.strip()
        if not conteudo or conteudo.startswith(("#", "---", "...")):
            continue
        if conteudo.startswith("- "):
            conteudo = conteudo[2:].strip()
            item = conteudo if conteudo.startswith(("'", '"')) else _sem_comentario(conteudo)
            if "=" in item and ": " not in item:
                chave, _, bruto = conteudo.partition("=")
                valor = _valor(bruto)
                if valor is not None:
                    entradas.append(EntradaDeConfiguracao(chave.strip(), valor, numero, linha))
                continue
        chave, separador, bruto = conteudo.partition(":")
        if not separador or not bruto.strip():
            continue  # inicio de mapeamento ou lista
        if not bruto.startswith((" ", "\t")):
            continue  # "http://..." sem espaco apos os dois pontos nao e par
        valor = _valor(bruto)
        if valor is None or valor.startswith(("|", ">", "&", "*", "[", "{")):
            continue
        entradas.append(
            EntradaDeConfiguracao(chave.strip().strip('"').strip("'"), valor, numero, linha)
        )
    return entradas


def ler_json(texto: str) -> list[EntradaDeConfiguracao]:
    """Todos os pares chave -> string do documento, com linha aproximada.

    O `json` da stdlib nao informa linha; ela e localizada procurando a
    chave (e o valor) no texto — so para exibicao, a deteccao usa o objeto.
    """
    dados = json.loads(texto)
    linhas = texto.splitlines()
    entradas: list[EntradaDeConfiguracao] = []

    def localizar(chave: str, valor: str) -> int:
        alvo_chave = json.dumps(chave)
        alvo_valor = json.dumps(valor)[1:-1]
        candidata = 1
        for numero, linha in enumerate(linhas, start=1):
            if alvo_chave in linha:
                if alvo_valor in linha:
                    return numero
                candidata = candidata if candidata > 1 else numero
        return candidata

    def visitar(no: object) -> None:
        if isinstance(no, dict):
            for chave, valor in no.items():
                if isinstance(valor, str):
                    numero = localizar(str(chave), valor)
                    texto_linha = linhas[numero - 1] if linhas else ""
                    entradas.append(EntradaDeConfiguracao(str(chave), valor, numero, texto_linha))
                else:
                    visitar(valor)
        elif isinstance(no, list):
            for item in no:
                visitar(item)

    visitar(dados)
    return entradas


def ler_configuracao(
    caminho: Path, raiz: Path | None = None
) -> ArquivoDeConfiguracao | FalhaDeLeitura:
    caminho = Path(caminho)
    base = Path(raiz) if raiz is not None else caminho.parent
    exibicao = caminho_relativo(caminho, base)
    formato = formato_de(caminho) or "env"
    try:
        if caminho.stat().st_size > TAMANHO_MAXIMO:
            return ArquivoDeConfiguracao(exibicao, formato, ())
        texto = caminho.read_text(encoding="utf-8")
    except UnicodeDecodeError as erro:
        return FalhaDeLeitura(arquivo=exibicao, motivo="codificacao", mensagem=str(erro))
    except OSError as erro:
        return FalhaDeLeitura(arquivo=exibicao, motivo="io", mensagem=str(erro))

    try:
        if formato == "json":
            entradas = ler_json(texto)
        elif formato == "yaml":
            entradas = ler_yaml(texto)
        else:
            entradas = ler_linhas_chave_valor(texto, formato)
    except json.JSONDecodeError as erro:
        return FalhaDeLeitura(
            arquivo=exibicao, motivo="sintaxe", mensagem=erro.msg, linha=erro.lineno
        )
    return ArquivoDeConfiguracao(exibicao, formato, tuple(entradas))


def ler_diretorio(
    raiz: Path,
) -> tuple[list[ArquivoDeConfiguracao], list[FalhaDeLeitura]]:
    raiz = Path(raiz)
    base = raiz if raiz.is_dir() else raiz.parent
    lidos: list[ArquivoDeConfiguracao] = []
    falhas: list[FalhaDeLeitura] = []
    for caminho in descobrir_configuracoes(raiz):
        resultado = ler_configuracao(caminho, base)
        if isinstance(resultado, FalhaDeLeitura):
            falhas.append(resultado)
        else:
            lidos.append(resultado)
    return lidos, falhas
