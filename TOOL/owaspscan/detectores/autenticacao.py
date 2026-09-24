"""Detectores de falhas de autenticacao e de protecao de credenciais.

Reune os detectores do tema "Authentication Failures". A classificacao OWASP
segue a CWE, nao o tema (ver CLAUDE.md):

- JWT aceito sem verificar assinatura ........ CWE-287  A07
- Hash rapido (md5/sha*) aplicado a senha .... CWE-916  A02
- Senha gravada ou comparada em texto puro ... CWE-256  A04
- Cookie sem Secure / sem HttpOnly ........... CWE-614 / CWE-1004  A05
- Sessao/token com validade excessiva ........ CWE-613  A07
- Login sem limite de tentativas (candidato) . CWE-307  A07
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.motor.catalogo import (
    CATALOGO_PADRAO,
    CHAMADAS_QUE_TRATAM_SENHA,
    COOKIE_HTTPONLY_CONFIG,
    COOKIE_SECURE_CONFIG,
    HASHES_RAPIDOS,
    LIMITES_DE_SESSAO,
    METODOS_DE_PERSISTENCIA,
    PALAVRAS_DE_BLOQUEIO,
    PALAVRAS_DE_COOKIE_SENSIVEL,
    PALAVRAS_DE_LOGIN,
    PALAVRAS_DE_SENHA,
    Catalogo,
    nome_pontilhado,
)
from owaspscan.motor.confianca import (
    confianca_para,
    justificativa,
    procedencias_relevantes,
)
from owaspscan.motor.estrutura import (
    argumento,
    atribuicoes_de_configuracao,
    caminhos_da_rota,
    funcoes_de_rota,
    mapa_de_importacoes,
    metodos_http,
    nome_qualificado,
    nomes_de_decoradores,
    tokens_de_nome,
    valor_constante,
)
from owaspscan.motor.taint import Escopo, nos_do_escopo


def _achado(
    arquivo: ArquivoAnalisado,
    no: ast.AST,
    cwe: str,
    severidade: str,
    confianca: str,
    descricao: str,
    recomendacao: str,
    trecho: str | None = None,
) -> Achado:
    return criar_achado(
        arquivo=arquivo.arquivo,
        linha=arquivo.linha_de(no),
        cwe=cwe,
        severidade=severidade,
        confianca=confianca,
        trecho=trecho if trecho is not None else arquivo.trecho_de(no),
        descricao=descricao,
        recomendacao=recomendacao,
    )


def _resolver(nome_ou_expr: ast.AST, escopos: tuple[Escopo | None, ...]) -> list[ast.AST]:
    """A expressao e, se for um nome, os valores atribuidos a ele a vista."""
    candidatos = [nome_ou_expr]
    nome = nome_pontilhado(nome_ou_expr)
    if nome:
        for escopo in escopos:
            if escopo is not None:
                candidatos.extend(escopo.atribuicoes.get(nome, ()))
    return candidatos


def menciona_senha(expressao: ast.AST) -> bool:
    """Algum identificador ou chave literal da expressao nomeia uma senha?"""
    for no in ast.walk(expressao):
        nome = None
        if isinstance(no, ast.Name):
            nome = no.id
        elif isinstance(no, ast.Attribute):
            nome = no.attr
        elif isinstance(no, ast.Subscript) and isinstance(valor_constante(no.slice), str):
            nome = no.slice.value
        if nome and set(tokens_de_nome(nome)) & PALAVRAS_DE_SENHA:
            return True
    return False


def _nomeia_senha(nome: str | None) -> bool:
    return bool(nome) and bool(set(tokens_de_nome(nome)) & PALAVRAS_DE_SENHA)


# --- JWT (CWE-287) ----------------------------------------------------------

RECOMENDACAO_JWT = (
    "Sempre verifique a assinatura: jwt.decode(token, CHAVE, "
    "algorithms=['HS256']). Nunca aceite o algoritmo 'none' nem desligue "
    "verify_signature; para ler o cabecalho antes de validar, use "
    "jwt.get_unverified_header e valide em seguida."
)


@dataclass(frozen=True)
class DetectorJwtSemVerificacao:
    """JWT decodificado sem verificacao de assinatura (CWE-287)."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "JWT sem verificacao"
    cwe: str = "CWE-287"

    def detectar(self, arquivo: ArquivoAnalisado, escopos: list[Escopo]) -> list[Achado]:
        importacoes = mapa_de_importacoes(arquivo.arvore)
        modulo = escopos[0] if escopos else None
        achados: list[Achado] = []
        for escopo in escopos:
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                qualificado = nome_qualificado(no.func, importacoes) or ""
                partes = qualificado.split(".")
                if "jwt" not in partes[:-1] or partes[-1] not in {"decode", "encode"}:
                    continue
                motivo = self._motivo(no, partes[-1], (escopo, modulo))
                if motivo:
                    achados.append(
                        _achado(
                            arquivo,
                            no,
                            self.cwe,
                            "alta",
                            "alta",
                            f"{qualificado} com {motivo}: qualquer pessoa pode forjar "
                            "um token com a identidade que quiser.",
                            RECOMENDACAO_JWT,
                        )
                    )
        return achados

    def _motivo(self, no: ast.Call, operacao: str, escopos) -> str | None:
        if operacao == "encode":
            alg = valor_constante(argumento(no, 2, "algorithm"))
            if isinstance(alg, str) and alg.lower() == "none":
                return "algorithm='none' (token sem assinatura)"
            return None
        if valor_constante(argumento(no, None, "verify")) is False:
            return "verify=False"
        opcoes = argumento(no, None, "options")
        if opcoes is not None:
            for candidato in _resolver(opcoes, escopos):
                if isinstance(candidato, ast.Dict):
                    for chave, valor in zip(candidato.keys, candidato.values):
                        if (
                            valor_constante(chave) == "verify_signature"
                            and valor_constante(valor) is False
                        ):
                            return "options={'verify_signature': False}"
        algoritmos = argumento(no, None, "algorithms")
        if isinstance(algoritmos, (ast.List, ast.Tuple)):
            for item in algoritmos.elts:
                texto = valor_constante(item)
                if isinstance(texto, str) and texto.lower() == "none":
                    return "algorithms contendo 'none'"
        return None


# --- Hash de senha fraco (CWE-916) -----------------------------------------

RECOMENDACAO_HASH = (
    "Use um hash de senha com custo ajustavel: werkzeug.security."
    "generate_password_hash, django make_password, bcrypt ou argon2. "
    "md5/sha1/sha256 sao rapidos demais: um vazamento do banco permite "
    "testar bilhoes de senhas por segundo."
)


@dataclass(frozen=True)
class DetectorHashDeSenhaFraco:
    """Senha passada a hash rapido do hashlib (CWE-916)."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Hash de senha fraco"
    cwe: str = "CWE-916"

    def detectar(self, arquivo: ArquivoAnalisado, escopos: list[Escopo]) -> list[Achado]:
        importacoes = mapa_de_importacoes(arquivo.arvore)
        achados: list[Achado] = []
        for escopo in escopos:
            hashers = self._nomes_de_hasher(escopo, importacoes)
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                qualificado = nome_qualificado(no.func, importacoes) or ""
                algoritmo = None
                argumentos: list[ast.AST] = []
                if qualificado in HASHES_RAPIDOS:
                    algoritmo, argumentos = qualificado, list(no.args)
                elif qualificado == "hashlib.new" and no.args:
                    nome = valor_constante(no.args[0])
                    if isinstance(nome, str) and f"hashlib.{nome.lower()}" in HASHES_RAPIDOS:
                        algoritmo, argumentos = f"hashlib.new('{nome}')", no.args[1:]
                elif (
                    isinstance(no.func, ast.Attribute)
                    and no.func.attr == "update"
                    and nome_pontilhado(no.func.value) in hashers
                ):
                    algoritmo = hashers[nome_pontilhado(no.func.value)]
                    argumentos = list(no.args)
                if algoritmo and any(menciona_senha(a) for a in argumentos):
                    achados.append(
                        _achado(
                            arquivo,
                            no,
                            self.cwe,
                            "alta",
                            # O que indica "senha" e o nome do identificador.
                            "media",
                            f"Senha passada a {algoritmo}, hash rapido e sem custo "
                            "ajustavel. Mesmo com sal, um banco vazado e quebrado "
                            "por forca bruta em GPU.",
                            RECOMENDACAO_HASH,
                        )
                    )
        return achados

    @staticmethod
    def _nomes_de_hasher(escopo: Escopo, importacoes: dict[str, str]) -> dict[str, str]:
        """`h = hashlib.sha256()` -> {"h": "hashlib.sha256"}, para seguir h.update()."""
        hashers: dict[str, str] = {}
        for nome, valores in escopo.atribuicoes.items():
            for valor in valores:
                if isinstance(valor, ast.Call):
                    qualificado = nome_qualificado(valor.func, importacoes) or ""
                    if qualificado in HASHES_RAPIDOS:
                        hashers[nome] = qualificado
        return hashers


# --- Senha em texto puro (CWE-256) -----------------------------------------

RECOMENDACAO_TEXTO_PURO = (
    "Nunca grave a senha recebida: grave generate_password_hash(senha) "
    "(ou make_password / bcrypt) e compare com check_password_hash, que "
    "tambem evita ataque de tempo."
)


@dataclass(frozen=True)
class DetectorSenhaEmTextoPuro:
    """Senha da requisicao gravada ou comparada sem hash (CWE-256)."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Senha em texto puro"
    cwe: str = "CWE-256"

    def detectar(self, arquivo: ArquivoAnalisado, escopos: list[Escopo]) -> list[Achado]:
        achados: list[Achado] = []
        for escopo in escopos:
            for no in nos_do_escopo(escopo):
                achado = None
                if isinstance(no, (ast.Assign, ast.AnnAssign)):
                    achado = self._da_atribuicao(arquivo, escopo, no)
                elif isinstance(no, ast.Call):
                    achado = self._da_persistencia(arquivo, escopo, no)
                elif isinstance(no, ast.Compare):
                    achado = self._da_comparacao(arquivo, escopo, no)
                if achado is not None:
                    achados.append(achado)
        return achados

    def _contaminada(self, escopo: Escopo, expressao: ast.AST):
        return procedencias_relevantes(
            escopo.procedencias_da_expressao(expressao), self.cwe, self.catalogo
        )

    def _gravacao(self, arquivo, escopo, no, valor, destino: str) -> Achado | None:
        procedencias = self._contaminada(escopo, valor)
        if not procedencias:
            return None
        fontes = ", ".join(sorted({p.fonte for p in procedencias}))
        return _achado(
            arquivo,
            no,
            self.cwe,
            "alta",
            confianca_para(procedencias),
            f"Senha vinda de {fontes} gravada em {destino} sem hash: qualquer "
            "acesso ao banco (backup, log, SQL Injection) expoe as senhas."
            + justificativa(procedencias),
            RECOMENDACAO_TEXTO_PURO,
        )

    def _da_atribuicao(self, arquivo, escopo, no) -> Achado | None:
        alvos = no.targets if isinstance(no, ast.Assign) else [no.target]
        if no.value is None:
            return None
        for alvo in alvos:
            # So atributos de objeto (user.password = ...): variavel local
            # com nome de senha e apenas a senha em transito.
            if isinstance(alvo, ast.Attribute) and _nomeia_senha(alvo.attr):
                return self._gravacao(arquivo, escopo, no, no.value, nome_pontilhado(alvo) or alvo.attr)
        return None

    def _da_persistencia(self, arquivo, escopo, no: ast.Call) -> Achado | None:
        func = no.func
        chamado = func.attr if isinstance(func, ast.Attribute) else (
            func.id if isinstance(func, ast.Name) else ""
        )
        if chamado in CHAMADAS_QUE_TRATAM_SENHA:
            return None
        construtor = isinstance(func, ast.Name) and chamado[:1].isupper()
        if not (construtor or chamado in METODOS_DE_PERSISTENCIA):
            return None
        for kw in no.keywords:
            if _nomeia_senha(kw.arg):
                return self._gravacao(arquivo, escopo, no, kw.value, f"{chamado}({kw.arg}=...)")
        return None

    def _da_comparacao(self, arquivo, escopo, no: ast.Compare) -> Achado | None:
        if not all(isinstance(op, (ast.Eq, ast.NotEq)) for op in no.ops):
            return None
        lados = [no.left, *no.comparators]
        armazenados = [
            lado
            for lado in lados
            if (isinstance(lado, ast.Attribute) and _nomeia_senha(lado.attr))
            or (
                isinstance(lado, ast.Subscript)
                and _nomeia_senha(valor_constante(lado.slice) if isinstance(valor_constante(lado.slice), str) else None)
                and not self._contaminada(escopo, lado)
            )
        ]
        if not armazenados:
            return None
        for lado in lados:
            if lado in armazenados:
                continue
            procedencias = self._contaminada(escopo, lado)
            if procedencias:
                fontes = ", ".join(sorted({p.fonte for p in procedencias}))
                return _achado(
                    arquivo,
                    no,
                    self.cwe,
                    "alta",
                    # Comparar em claro implica senha guardada em claro, mas
                    # o campo pode ter outro significado: confianca media.
                    "media",
                    f"Senha vinda de {fontes} comparada diretamente com o campo "
                    "armazenado: indica senha guardada em texto puro, e a "
                    "comparacao com == ainda vaza informacao por tempo.",
                    RECOMENDACAO_TEXTO_PURO,
                )
        return None


# --- Cookies (CWE-614, CWE-1004) -------------------------------------------

RECOMENDACAO_COOKIE = (
    "Cookies de sessao e autenticacao devem ter Secure (so trafegam em HTTPS) "
    "e HttpOnly (JavaScript nao le): resp.set_cookie(nome, valor, secure=True, "
    "httponly=True, samesite='Lax'); SESSION_COOKIE_SECURE = True."
)


@dataclass(frozen=True)
class DetectorCookieInseguro:
    """Cookie sem Secure (CWE-614) ou sem HttpOnly (CWE-1004).

    Emite as duas CWEs; `cwe` nomeia a primeira por compatibilidade com o
    protocolo de detector.
    """

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Cookie inseguro"
    cwe: str = "CWE-614"

    def detectar(self, arquivo: ArquivoAnalisado, escopos: list[Escopo]) -> list[Achado]:
        achados: list[Achado] = []
        for atribuicao in atribuicoes_de_configuracao(arquivo.arvore):
            if valor_constante(atribuicao.valor) is not False:
                continue
            if atribuicao.chave in COOKIE_SECURE_CONFIG:
                achados.append(self._secure(arquivo, atribuicao.no, "alta", f"{atribuicao.chave} = False"))
            elif atribuicao.chave in COOKIE_HTTPONLY_CONFIG:
                achados.append(self._httponly(arquivo, atribuicao.no, "alta", f"{atribuicao.chave} = False"))

        for escopo in escopos:
            for no in nos_do_escopo(escopo):
                if (
                    isinstance(no, ast.Call)
                    and isinstance(no.func, ast.Attribute)
                    and no.func.attr == "set_cookie"
                ):
                    achados += self._do_set_cookie(arquivo, no)
        return achados

    def _do_set_cookie(self, arquivo, no: ast.Call) -> list[Achado]:
        nome = valor_constante(argumento(no, 0, "key"))
        sensivel = isinstance(nome, str) and bool(
            set(tokens_de_nome(nome)) & PALAVRAS_DE_COOKIE_SENSIVEL
        )
        achados: list[Achado] = []
        for palavra, montar in (("secure", self._secure), ("httponly", self._httponly)):
            presente = any(kw.arg == palavra for kw in no.keywords)
            valor = valor_constante(argumento(no, None, palavra))
            if presente and valor is False:
                achados.append(montar(arquivo, no, "alta", f"set_cookie({palavra}=False)"))
            elif not presente and sensivel:
                achados.append(
                    montar(arquivo, no, "media", f"set_cookie('{nome}') sem {palavra}=True")
                )
        return achados

    def _secure(self, arquivo, no, confianca, origem) -> Achado:
        return _achado(
            arquivo, no, "CWE-614", "media", confianca,
            f"{origem}: o cookie tambem trafega em HTTP sem TLS e pode ser "
            "capturado na rede.",
            RECOMENDACAO_COOKIE,
        )

    def _httponly(self, arquivo, no, confianca, origem) -> Achado:
        return _achado(
            arquivo, no, "CWE-1004", "media", confianca,
            f"{origem}: JavaScript da pagina le o cookie, e um XSS passa a "
            "roubar a sessao.",
            RECOMENDACAO_COOKIE,
        )


# --- Expiracao de sessao (CWE-613) -----------------------------------------

RECOMENDACAO_EXPIRACAO = (
    "Limite a validade: sessoes de ate alguns dias (PERMANENT_SESSION_LIFETIME"
    " = timedelta(hours=12)) e tokens de acesso de minutos a poucas horas, "
    "renovados por refresh token."
)

_UNIDADES = {"weeks": 604800, "days": 86400, "hours": 3600, "minutes": 60, "seconds": 1}


def avaliar_duracao(no: ast.AST) -> float | None:
    """Duracao em segundos de literais, aritmetica simples e timedelta()."""
    valor = valor_constante(no)
    if isinstance(valor, (int, float)) and not isinstance(valor, bool):
        return float(valor)
    if isinstance(no, ast.BinOp) and isinstance(no.op, (ast.Mult, ast.Add)):
        esquerda, direita = avaliar_duracao(no.left), avaliar_duracao(no.right)
        if esquerda is None or direita is None:
            return None
        return esquerda * direita if isinstance(no.op, ast.Mult) else esquerda + direita
    if isinstance(no, ast.Call):
        pontilhado = nome_pontilhado(no.func) or ""
        if pontilhado.split(".")[-1] != "timedelta":
            return None
        total = 0.0
        for posicao, unidade in enumerate(("days", "seconds")):
            if posicao < len(no.args):
                parcial = avaliar_duracao(no.args[posicao])
                if parcial is None:
                    return None
                total += parcial * _UNIDADES[unidade]
        for kw in no.keywords:
            if kw.arg not in _UNIDADES:
                return None
            parcial = avaliar_duracao(kw.value)
            if parcial is None:
                return None
            total += parcial * _UNIDADES[kw.arg]
        return total
    return None


def _em_texto(segundos: float) -> str:
    if segundos >= 86400:
        return f"{segundos / 86400:g} dias"
    return f"{segundos / 3600:g} horas"


@dataclass(frozen=True)
class DetectorExpiracaoDeSessao:
    """Sessao ou token de acesso com validade excessiva (CWE-613)."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Expiracao de sessao"
    cwe: str = "CWE-613"

    def detectar(self, arquivo: ArquivoAnalisado, escopos: list[Escopo]) -> list[Achado]:
        achados: list[Achado] = []
        for atribuicao in atribuicoes_de_configuracao(arquivo.arvore):
            limite = LIMITES_DE_SESSAO.get(atribuicao.chave)
            if limite is None:
                continue
            if valor_constante(atribuicao.valor) is False:
                descricao = f"{atribuicao.chave} = False: o token nunca expira."
            else:
                segundos = avaliar_duracao(atribuicao.valor)
                if segundos is None:
                    continue
                if atribuicao.chave.endswith("_MINUTES"):
                    segundos *= 60
                if segundos <= limite:
                    continue
                descricao = (
                    f"{atribuicao.chave} de {_em_texto(segundos)}, acima do limite "
                    f"adotado ({_em_texto(limite)}): uma credencial roubada "
                    "continua valida por tempo demais."
                )
            achados.append(
                _achado(
                    arquivo, atribuicao.no, self.cwe, "baixa", "alta",
                    descricao, RECOMENDACAO_EXPIRACAO,
                )
            )
        return achados


# --- Tentativas de login (CWE-307) -----------------------------------------

PREFIXO_CANDIDATO_307 = "Candidato a login sem limite de tentativas (requer revisao manual):"

RECOMENDACAO_TENTATIVAS = (
    "Limite tentativas por usuario e por IP: @limiter.limit('5/minute') do "
    "Flask-Limiter, django-axes, ou bloqueio temporario apos N falhas."
)


@dataclass(frozen=True)
class DetectorLoginSemLimite:
    """Rota de login sem limite de tentativas visivel (CWE-307). Candidatos."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Login sem limite de tentativas"
    cwe: str = "CWE-307"

    def detectar(self, arquivo: ArquivoAnalisado, escopos: list[Escopo]) -> list[Achado]:
        if self._limite_global(arquivo.arvore):
            return []
        achados: list[Achado] = []
        for funcao in funcoes_de_rota(arquivo.arvore):
            palavras = set(tokens_de_nome(funcao.name))
            for caminho in caminhos_da_rota(funcao):
                for segmento in caminho.split("/"):
                    palavras.update(tokens_de_nome(segmento))
            if not palavras & PALAVRAS_DE_LOGIN:
                continue
            if "POST" not in metodos_http(funcao):
                continue
            decoradores = " ".join(nomes_de_decoradores(funcao)).lower()
            if any(t in decoradores for t in ("limit", "throttle", "ratelimit")):
                continue
            if self._conta_tentativas(funcao):
                continue
            achados.append(
                _achado(
                    arquivo,
                    funcao,
                    self.cwe,
                    "media",
                    "baixa",
                    f"{PREFIXO_CANDIDATO_307} a rota {funcao.name} recebe credenciais "
                    "sem decorator de rate limit nem contagem de tentativas. O "
                    "limite pode estar no proxy/WAF, por isso este achado NAO "
                    "afirma vulnerabilidade.",
                    RECOMENDACAO_TENTATIVAS,
                    trecho=f"def {funcao.name}(...)",
                )
            )
        return achados

    @staticmethod
    def _limite_global(arvore: ast.AST) -> bool:
        """Limiter(..., default_limits=[...]) vale para todas as rotas."""
        for no in ast.walk(arvore):
            if isinstance(no, ast.Call):
                pontilhado = nome_pontilhado(no.func) or ""
                if pontilhado.split(".")[-1] == "Limiter" and any(
                    kw.arg in {"default_limits", "application_limits"} for kw in no.keywords
                ):
                    return True
        return False

    @staticmethod
    def _conta_tentativas(funcao: ast.AST) -> bool:
        for no in ast.walk(funcao):
            nome = no.id if isinstance(no, ast.Name) else (
                no.attr if isinstance(no, ast.Attribute) else None
            )
            if nome and set(tokens_de_nome(nome)) & PALAVRAS_DE_BLOQUEIO:
                return True
        return False
