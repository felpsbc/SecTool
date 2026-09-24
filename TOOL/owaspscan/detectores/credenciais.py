"""Detector de credenciais fixas no codigo (CWE-798 -> A07:2021).

Procura segredos escritos como literal no codigo-fonte — o padrao que
assistentes de codigo mais produzem: `SECRET_KEY = "dev"`, usuario de teste
`create_user("admin", "admin@x", "admin123")`, `password="123456"` numa
conexao, `if senha == "master":`.

Formas reconhecidas (todas pela AST):

- atribuicao a nome/atributo/chave com nome de credencial;
- argumento nomeado (`password="..."`) e chave de dicionario literal;
- valor padrao de parametro (`def conectar(senha="root")`);
- fallback de variavel de ambiente (`os.getenv("SECRET_KEY", "dev")`) —
  confianca media: em producao a variavel pode existir;
- `auth=("usuario", "senha")`, `HTTPBasicAuth(u, "senha")`, `smtp.login(u, "senha")`;
- `create_user`/`create_superuser` com senha posicional;
- comparacao com literal (`senha == "admin123"`): senha-mestra/backdoor;
- URL com senha embutida (`postgres://app:s3nh4@db/app`).

O trecho do relatorio MASCARA o segredo: a ferramenta nao pode ser o
vazamento que ela denuncia.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from urllib.parse import urlsplit

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo, nome_pontilhado
from owaspscan.motor.credenciais import (
    e_segredo_plausivel,
    mascarar,
    nomeia_credencial,
    url_com_senha,
)
from owaspscan.motor.estrutura import valor_constante

RECOMENDACAO = (
    "Tire o segredo do codigo: leia de variavel de ambiente sem valor padrao "
    "(os.environ['SECRET_KEY'], falhando se ausente) ou de um cofre (Vault, "
    "AWS Secrets Manager). Usuarios de teste devem nascer em fixtures fora "
    "do codigo de producao, com senha gerada. Um segredo que ja foi "
    "commitado deve ser considerado vazado: revogue e gere outro."
)

# Leitura de ambiente com valor padrao: (funcao, posicao do nome, posicao do padrao).
_LEITURAS_DE_AMBIENTE = {
    "getenv": (0, 1, "default"),
    "get": (0, 1, "default"),  # os.environ.get
    "config": (0, None, "default"),  # python-decouple
    "env": (0, 1, "default"),  # django-environ
    "str": (0, 1, "default"),  # environs: env.str("X", "padrao")
}

_CLASSES_DE_AUTH = frozenset({"HTTPBasicAuth", "HTTPDigestAuth", "BasicAuth", "HTTPProxyAuth"})
_CRIACAO_DE_USUARIO = {"create_user": 2, "create_superuser": 2, "set_password": 0}


def _texto(no: ast.AST | None) -> str | None:
    valor = valor_constante(no)
    return valor if isinstance(valor, str) else None


@dataclass(frozen=True)
class DetectorCredenciais:
    """Detector de CWE-798 em codigo Python."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Hard-coded Credentials"
    cwe: str = "CWE-798"

    def detectar(self, arquivo: ArquivoAnalisado, escopos) -> list[Achado]:
        achados: dict[int, Achado] = {}  # id do literal -> achado (um por literal)

        def registrar(
            no,
            literal: ast.Constant,
            confianca: str,
            descricao: str,
            segredo: str | None = None,
            trecho: str | None = None,
        ) -> None:
            if id(literal) in achados:
                return
            base = trecho if trecho is not None else arquivo.trecho_de(no)
            trecho = mascarar(base, segredo if segredo is not None else literal.value)
            achados[id(literal)] = criar_achado(
                arquivo=arquivo.arquivo,
                linha=arquivo.linha_de(literal),
                cwe=self.cwe,
                severidade="alta",
                confianca=confianca,
                trecho=trecho,
                descricao=descricao,
                recomendacao=RECOMENDACAO,
            )

        def credencial(
            no, nome, literal, confianca="alta", como="atribuido a", trecho=None
        ) -> None:
            if (
                isinstance(literal, ast.Constant)
                and nomeia_credencial(nome)
                and e_segredo_plausivel(literal.value)
            ):
                registrar(
                    no,
                    literal,
                    confianca,
                    f"Credencial fixa no codigo: literal {como} '{nome}'. Qualquer "
                    "pessoa com acesso ao repositorio (ou a um fork, backup ou "
                    "imagem de container) passa a ter o segredo.",
                    trecho=trecho,
                )

        # Docstrings e strings soltas documentam, nao configuram: uma URL de
        # exemplo num docstring nao e credencial em uso.
        documentacao = {
            id(no.value)
            for no in ast.walk(arquivo.arvore)
            if isinstance(no, ast.Expr) and isinstance(no.value, ast.Constant)
        }

        for no in ast.walk(arquivo.arvore):
            match no:
                case ast.Assign(targets=alvos, value=valor):
                    for alvo in alvos:
                        credencial(no, self._nome_do_alvo(alvo), valor)
                        self._desempacotar(no, alvo, valor, credencial)
                case ast.AnnAssign(target=alvo, value=valor) if valor is not None:
                    credencial(no, self._nome_do_alvo(alvo), valor)
                case ast.Dict(keys=chaves, values=valores):
                    for chave, valor in zip(chaves, valores):
                        credencial(no, _texto(chave), valor, como="na chave")
                case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.Lambda():
                    self._padroes_de_parametro(no, credencial)
                case ast.Call():
                    self._da_chamada(no, credencial, registrar)
                case ast.Compare():
                    self._da_comparacao(no, registrar)
                case ast.Constant(value=str() as valor) if id(no) not in documentacao:
                    esquema = url_com_senha(valor)
                    if esquema:
                        registrar(
                            no,
                            no,
                            "alta",
                            f"URL {esquema}:// com senha embutida no codigo. Leia a "
                            "URL inteira de variavel de ambiente.",
                            segredo=urlsplit(valor.strip()).password,
                        )
        return sorted(achados.values(), key=lambda a: (a.linha, a.trecho))

    @staticmethod
    def _nome_do_alvo(alvo: ast.AST) -> str | None:
        if isinstance(alvo, ast.Name):
            return alvo.id
        if isinstance(alvo, ast.Attribute):
            return alvo.attr
        if isinstance(alvo, ast.Subscript):
            return _texto(alvo.slice)
        return None

    def _desempacotar(self, no, alvo, valor, credencial) -> None:
        """`usuario, senha = "admin", "123"`."""
        if isinstance(alvo, (ast.Tuple, ast.List)) and isinstance(valor, (ast.Tuple, ast.List)):
            for item_alvo, item_valor in zip(alvo.elts, valor.elts):
                credencial(no, self._nome_do_alvo(item_alvo), item_valor)

    @staticmethod
    def _padroes_de_parametro(no, credencial) -> None:
        argumentos = no.args
        posicionais = [*argumentos.posonlyargs, *argumentos.args]
        pares = list(
            zip(posicionais[len(posicionais) - len(argumentos.defaults):], argumentos.defaults)
        )
        pares += [
            (arg, padrao)
            for arg, padrao in zip(argumentos.kwonlyargs, argumentos.kw_defaults)
            if padrao is not None
        ]
        funcao = getattr(no, "name", "lambda")
        for arg, padrao in pares:
            valor = valor_constante(padrao)
            credencial(
                no,
                arg.arg,
                padrao,
                como="como valor padrao do parametro",
                trecho=f"def {funcao}(..., {arg.arg}={valor!r})",
            )

    def _da_chamada(self, no: ast.Call, credencial, registrar) -> None:
        func = no.func
        chamado = func.attr if isinstance(func, ast.Attribute) else (
            func.id if isinstance(func, ast.Name) else None
        )

        # password="..." em qualquer chamada; auth=("u", "p").
        for kw in no.keywords:
            if kw.arg == "auth" and isinstance(kw.value, ast.Tuple) and len(kw.value.elts) == 2:
                self._par_de_auth(no, kw.value.elts[1], registrar)
            else:
                credencial(no, kw.arg, kw.value, como="no argumento")

        # os.getenv("SECRET_KEY", "dev"): o padrao e credencial fixa.
        if chamado in _LEITURAS_DE_AMBIENTE:
            pos_nome, pos_padrao, palavra = _LEITURAS_DE_AMBIENTE[chamado]
            nome = _texto(no.args[pos_nome]) if len(no.args) > pos_nome else None
            padrao = None
            if pos_padrao is not None and len(no.args) > pos_padrao:
                padrao = no.args[pos_padrao]
            for kw in no.keywords:
                if kw.arg == palavra:
                    padrao = kw.value
            if padrao is not None and self._e_leitura_de_ambiente(no, chamado):
                credencial(
                    no,
                    nome,
                    padrao,
                    confianca="media",
                    como="como valor padrao da variavel de ambiente",
                )

        if chamado in _CLASSES_DE_AUTH and len(no.args) >= 2:
            self._par_de_auth(no, no.args[1], registrar)
        if chamado == "login" and isinstance(func, ast.Attribute) and len(no.args) >= 2:
            # smtplib/ftplib/imaplib: servidor.login(usuario, senha)
            self._par_de_auth(no, no.args[1], registrar)
        if chamado in _CRIACAO_DE_USUARIO:
            posicao = _CRIACAO_DE_USUARIO[chamado]
            if len(no.args) > posicao:
                credencial(no, "password", no.args[posicao], como=f"como senha de {chamado}")

    @staticmethod
    def _e_leitura_de_ambiente(no: ast.Call, chamado: str) -> bool:
        """Evita tratar qualquer `.get(chave, padrao)` de dicionario como ambiente."""
        if chamado != "get":
            return True
        receptor = nome_pontilhado(no.func.value) if isinstance(no.func, ast.Attribute) else None
        return bool(receptor) and receptor.split(".")[-1] == "environ"

    @staticmethod
    def _par_de_auth(no, literal, registrar) -> None:
        if isinstance(literal, ast.Constant) and e_segredo_plausivel(literal.value):
            registrar(
                no,
                literal,
                "alta",
                "Senha fixa passada como credencial de autenticacao (auth/login) "
                "diretamente no codigo.",
            )

    @staticmethod
    def _da_comparacao(no: ast.Compare, registrar) -> None:
        if not all(isinstance(op, (ast.Eq, ast.NotEq)) for op in no.ops):
            return
        lados = [no.left, *no.comparators]
        nomes = [DetectorCredenciais._nome_do_alvo(lado) for lado in lados]
        if not any(nomeia_credencial(n) for n in nomes):
            return
        for lado in lados:
            if isinstance(lado, ast.Constant) and e_segredo_plausivel(lado.value):
                registrar(
                    no,
                    lado,
                    "alta",
                    "Credencial comparada com literal fixo: funciona como "
                    "senha-mestra (backdoor) que nao pode ser trocada sem novo deploy.",
                )


# --- Arquivos de configuracao ----------------------------------------------


@dataclass(frozen=True)
class DetectorCredenciaisEmConfiguracao:
    """CWE-798 em .env, YAML, JSON, INI, TOML e .properties.

    Nao segue o protocolo de `Detector` (que recebe AST): recebe o arquivo
    ja lido por `owaspscan.configuracao`. Mesmas regras de nome e valor do
    detector de codigo. Em arquivo-modelo (`.env.example`) o achado cai
    para severidade baixa: o valor deveria ser ficticio, mas vale conferir.
    """

    nome: str = "Hard-coded Credentials (configuracao)"
    cwe: str = "CWE-798"

    def detectar(self, configuracao) -> list[Achado]:
        achados: list[Achado] = []
        for entrada in configuracao.entradas:
            if nomeia_credencial(entrada.chave) and e_segredo_plausivel(entrada.valor):
                segredo = entrada.valor
                descricao = (
                    f"Credencial fixa em arquivo de configuracao: '{entrada.chave}'. "
                    "Arquivo versionado e segredo publicado para todo o repositorio."
                )
            elif esquema := url_com_senha(entrada.valor):
                segredo = urlsplit(entrada.valor.strip()).password
                descricao = (
                    f"URL {esquema}:// com senha embutida em '{entrada.chave}'."
                )
            else:
                continue
            exemplo = configuracao.e_exemplo
            if exemplo:
                descricao += (
                    " O arquivo e um modelo (.example/.sample): confirme que o "
                    "valor e ficticio e troque por um placeholder evidente."
                )
            achados.append(
                criar_achado(
                    arquivo=configuracao.arquivo,
                    linha=entrada.linha,
                    cwe=self.cwe,
                    severidade="baixa" if exemplo else "alta",
                    confianca="media" if exemplo else "alta",
                    trecho=mascarar(" ".join(entrada.texto.split()), segredo)[:120],
                    descricao=descricao,
                    recomendacao=RECOMENDACAO
                    + " Mantenha .env fora do git (.gitignore) e versione apenas "
                    "um .env.example com placeholders.",
                )
            )
        return achados
