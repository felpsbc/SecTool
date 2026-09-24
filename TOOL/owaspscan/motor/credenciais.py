"""Regras compartilhadas para reconhecer credenciais fixas (CWE-798).

Usadas tanto no codigo Python (via AST) quanto em arquivos de configuracao
(.env, YAML, JSON...). A decisao tem duas metades independentes:

1. o NOME diz que o valor e credencial (`db_password`, `API_KEY`, `senha`),
   e nao metadado sobre ela (`password_url`, `token_type`, `senha_minima`);
2. o VALOR e um segredo plausivel, e nao placeholder (`${DB_PASS}`,
   `<sua-chave>`, `****`) nem referencia (caminho, nome de variavel).

As duas metades inspecionam valores ja extraidos pelo parser (AST ou parser
do formato). Nada aqui le codigo-fonte por expressao regular.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from owaspscan.motor.estrutura import tokens_de_nome

PALAVRAS_DE_CREDENCIAL: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pw",
        "pass",
        "senha",
        "passphrase",
        "secret",
        "secreto",
        "segredo",
        "token",
        "apikey",
        "credential",
        "credentials",
        "credencial",
        "credenciais",
    }
)

# Pares de palavras que so juntos indicam credencial: "key" sozinho e comum.
BIGRAMAS_DE_CREDENCIAL: frozenset[tuple[str, str]] = frozenset(
    {
        ("api", "key"),
        ("private", "key"),
        ("access", "key"),
        ("secret", "key"),
        ("signing", "key"),
        ("encryption", "key"),
        ("master", "key"),
        ("chave", "api"),
        ("chave", "secreta"),
        ("chave", "privada"),
        ("client", "secret"),
    }
)

# Ultima palavra que transforma o nome em METADADO da credencial.
SUFIXOS_DE_METADADO: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "field",
        "fields",
        "campo",
        "name",
        "nome",
        "label",
        "length",
        "len",
        "min",
        "max",
        "minimo",
        "minima",
        "maximo",
        "size",
        "file",
        "arquivo",
        "path",
        "dir",
        "env",
        "var",
        "header",
        "type",
        "tipo",
        "prefix",
        "suffix",
        "pattern",
        "regex",
        "format",
        "template",
        "hint",
        "help",
        "msg",
        "message",
        "mensagem",
        "placeholder",
        "expires",
        "expiry",
        "expiration",
        "ttl",
        "timeout",
        "lifetime",
        "age",
        "count",
        "attempts",
        "column",
        "param",
        "policy",
        "required",
        "validator",
        "validators",
        "rules",
        "location",
        "id",
        "class",
        "backend",
        "backends",
        "hashers",
        "algorithm",
        "algorithms",
        "enabled",
        # Nome de arquivo ("flask_api_token.py") nao e nome de credencial.
        "py",
        "json",
        "yml",
        "yaml",
        "txt",
        "html",
        "csv",
        "xml",
        "md",
        "cfg",
        "ini",
        "toml",
        "log",
    }
)

# Prefixos de nome que indicam flag booleana, nao credencial.
PREFIXOS_DE_FLAG: frozenset[str] = frozenset({"is", "has", "use", "enable", "require"})

TAMANHO_MINIMO = 3

_PLACEHOLDERS_EXATOS: frozenset[str] = frozenset(
    {
        "none",
        "null",
        "nil",
        "undefined",
        "todo",
        "tbd",
        "fixme",
        "empty",
        "vazio",
        "redacted",
        "hidden",
        "secret-here",
        "insira-aqui",
    }
)


def nomeia_credencial(nome: str | None) -> bool:
    """O identificador (ou chave) nomeia um segredo?"""
    if not nome:
        return False
    palavras = tokens_de_nome(nome)
    if not palavras:
        return False
    if palavras[-1] in SUFIXOS_DE_METADADO or palavras[0] in PREFIXOS_DE_FLAG:
        return False
    if set(palavras) & PALAVRAS_DE_CREDENCIAL:
        return True
    pares = set(zip(palavras, palavras[1:]))
    # "chave_api" e "api_key" sao a mesma coisa em ordens diferentes.
    pares |= {(b, a) for a, b in pares}
    return bool(pares & BIGRAMAS_DE_CREDENCIAL)


def e_placeholder(valor: str) -> bool:
    """O valor e marcador de lugar, e nao um segredo real?"""
    texto = valor.strip()
    baixo = texto.lower()
    if len(texto) < TAMANHO_MINIMO:
        return True
    if baixo in _PLACEHOLDERS_EXATOS:
        return True
    if len(set(texto)) == 1:  # "****", "xxxx", "0000"
        return True
    # Interpolacao de variavel de ambiente ou template.
    if texto.startswith(("${", "{{", "%(", "$(")) or (texto.startswith("$") and texto[1:].replace("_", "").isalnum()):
        return True
    if texto.startswith("<") and texto.endswith(">"):
        return True
    if "your" in baixo or "seu_" in baixo or "sua_" in baixo or "sua-" in baixo or "seu-" in baixo:
        return True
    if baixo.startswith(("example", "exemplo", "changeme_in_", "replace")):
        return True
    return False


def parece_referencia(valor: str) -> bool:
    """O valor aponta para onde o segredo esta, em vez de conte-lo?"""
    texto = valor.strip()
    if any(c.isspace() for c in texto):
        return True  # frase: mensagem, label, texto de ajuda
    if texto.startswith(("/", "./", "../", "~/")):
        return True  # caminho de arquivo de segredo
    if "://" in texto:
        return True  # URL: tratada a parte, por url_com_senha
    # Nome de variavel de ambiente: "DB_PASSWORD".
    if texto.isupper() and "_" in texto and texto.replace("_", "").isalnum():
        return True
    return False


def e_segredo_plausivel(valor: object) -> bool:
    """Valor literal que deve ser tratado como credencial exposta."""
    return (
        isinstance(valor, str)
        and not e_placeholder(valor)
        and not parece_referencia(valor)
    )


def url_com_senha(valor: object) -> str | None:
    """Esquema da URL que embute senha (`postgres://u:SENHA@host`), ou None."""
    if not isinstance(valor, str) or "://" not in valor or "@" not in valor:
        return None
    if any(c.isspace() for c in valor.strip()):
        return None
    try:
        partes = urlsplit(valor.strip())
        senha = partes.password
        host = partes.hostname
    except ValueError:
        return None
    if not senha or not host or e_placeholder(senha):
        return None
    return partes.scheme or "url"


def mascarar(texto: str, segredo: str) -> str:
    """Troca o segredo por uma versao mascarada, para nao vaza-lo no relatorio."""
    if not segredo:
        return texto
    visivel = segredo[:2] if len(segredo) > 6 else ""
    return texto.replace(segredo, f"{visivel}***")
