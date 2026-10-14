"""Motor de taint generico sobre a arvore do tree-sitter.

Mesmas regras de aproximacao do motor Python (`owaspscan.motor.taint`),
declaradas de proposito:

1. Intraprocedural: cada funcao e um escopo. Funcoes aninhadas herdam o
   taint do escopo que as contem (closures sao a norma em JavaScript:
   `app.get(..., (req, res) => {...})`), mas taint nao volta delas.
2. Insensivel a fluxo: nome contaminado em algum ponto conta como
   contaminado no escopo inteiro.
3. Chamada desconhecida propaga, marcando `via_chamada` (confianca media).

As `Procedencia`s sao as mesmas do motor Python, para que confianca e
justificativa (`owaspscan.motor.confianca`) funcionem igual nas duas pontas.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from owaspscan.motor.taint import Procedencia
from owaspscan.poliglota.fonte import ArquivoPoliglota
from owaspscan.poliglota.perfil import CONVERSAO_NUMERICA, Atribuicao, Perfil, casa_algum

LIMITE_DE_ITERACOES = 10  # ponto fixo: cadeias a = b; b = c; c = fonte


def prefixos(nome: str) -> list[str]:
    """"a.b.c" -> ["a.b.c", "a.b", "a"]: atributo de objeto contaminado tambem e."""
    partes = nome.split(".")
    return [".".join(partes[:i]) for i in range(len(partes), 0, -1)]


@dataclass
class EscopoPoliglota:
    nome: str
    no: object  # tree_sitter.Node
    perfil: Perfil
    contaminados: dict[str, frozenset[Procedencia]] = field(default_factory=dict)
    nos: list = field(default_factory=list)  # nos do escopo, sem os aninhados

    def procedencias_de_nome(self, nome: str | None) -> frozenset[Procedencia]:
        if nome is None:
            return frozenset()
        for prefixo in prefixos(nome):
            fonte = casa_algum(self.perfil.fontes, prefixo)
            if fonte is not None:
                return frozenset({Procedencia(fonte=fonte)})
            conhecidas = self.contaminados.get(prefixo)
            if conhecidas:
                return conhecidas
        return frozenset()

    def procedencias_da_expressao(self, no) -> frozenset[Procedencia]:
        return _procedencias(no, self)

    def nomes_contaminados_em(self, no) -> frozenset[str]:
        """Raizes dos nomes contaminados citados na expressao (para guardas)."""
        encontrados: set[str] = set()
        pilha = [no]
        while pilha:
            atual = pilha.pop()
            if atual.type in self.perfil.fronteiras:
                continue
            nome = self.perfil.nome(atual)
            if nome is not None and self.procedencias_de_nome(nome):
                encontrados.add(nome.split(".")[0])
            pilha.extend(atual.named_children)
        return frozenset(encontrados)


def _procedencias(no, escopo: EscopoPoliglota) -> frozenset[Procedencia]:
    perfil = escopo.perfil
    if no is None or no.type in perfil.fronteiras:
        return frozenset()

    convertida = perfil.conversao_numerica(no)
    if convertida is not None:
        return frozenset(
            p.com_sanitizador(CONVERSAO_NUMERICA)
            for p in _procedencias(convertida, escopo)
        )

    chamada = perfil.chamada(no)
    if chamada is not None:
        fonte = casa_algum(perfil.fontes_de_chamada, chamada.nome)
        if fonte is not None:
            return frozenset({Procedencia(fonte=fonte)})
        internas: frozenset[Procedencia] = frozenset()
        for argumento in chamada.argumentos:
            internas |= _procedencias(argumento, escopo)
        if chamada.receptor is not None:
            internas |= _procedencias(chamada.receptor, escopo)
        sanitizador = perfil.sanitizador(chamada.nome)
        if sanitizador is not None:
            return frozenset(p.com_sanitizador(sanitizador[0]) for p in internas)
        if casa_algum(perfil.repassadores, chamada.nome) is not None:
            return internas
        return frozenset(replace(p, via_chamada=True) for p in internas)

    nome = perfil.nome(no)
    if nome is not None:
        conhecidas = escopo.procedencias_de_nome(nome)
        if conhecidas or not no.named_children:
            return conhecidas
        # Acesso cujo objeto nao e nome conhecido (`f(x).campo`): desce so no
        # objeto. Descer na propriedade confundiria `obj.id` com a variavel `id`.
        objeto = no.child_by_field_name("object") or no.named_children[0]
        return _procedencias(objeto, escopo)

    resultado: frozenset[Procedencia] = frozenset()
    for filho in no.named_children:
        resultado |= _procedencias(filho, escopo)
    return resultado


def _coletar(raiz, perfil: Perfil) -> tuple[list, list]:
    """Nos do escopo e as fronteiras (funcoes) aninhadas diretamente nele."""
    nos: list = []
    aninhadas: list = []
    pilha = list(reversed(raiz.named_children))
    while pilha:
        atual = pilha.pop()
        if atual.type in perfil.fronteiras:
            aninhadas.append(atual)
            continue
        nos.append(atual)
        pilha.extend(reversed(atual.named_children))
    return nos, aninhadas


def _condicional(no, raiz, perfil: Perfil) -> bool:
    atual = no.parent
    while atual is not None and atual != raiz:
        if atual.type in perfil.controle:
            return True
        atual = atual.parent
    return False


def _nome_do_escopo(no) -> str:
    nome = no.child_by_field_name("name")
    if nome is not None:
        return nome.text.decode("utf-8", "replace")
    return "<anonima>"


def _atribuicoes(nos: list, perfil: Perfil) -> list[Atribuicao]:
    encontradas: list[Atribuicao] = []
    for no in nos:
        atribuicao = perfil.atribuicao(no)
        if atribuicao is not None:
            encontradas.append(atribuicao)
            continue
        chamada = perfil.chamada(no)
        if (
            chamada is not None
            and chamada.receptor is not None
            and casa_algum(perfil.mutadores, chamada.nome) is not None
        ):
            alvo = perfil.nome(chamada.receptor)
            if alvo is not None:
                encontradas.append(Atribuicao(alvos=(alvo,), valor=no))
    return encontradas


def analisar_taint_poliglota(
    arquivo: ArquivoPoliglota, perfil: Perfil
) -> list[EscopoPoliglota]:
    """Escopos do arquivo (modulo primeiro), com os nomes contaminados."""
    escopos: list[EscopoPoliglota] = []

    def analisar(raiz, nome: str, herdados: dict[str, frozenset[Procedencia]]) -> None:
        nos, aninhadas = _coletar(raiz, perfil)
        escopo = EscopoPoliglota(
            nome=nome, no=raiz, perfil=perfil, contaminados=dict(herdados), nos=nos
        )
        for parametro, rotulo in perfil.parametros_contaminados(raiz).items():
            escopo.contaminados[parametro] = frozenset({Procedencia(fonte=rotulo)})

        atribuicoes = [
            (a, _condicional(a.valor, raiz, perfil)) for a in _atribuicoes(nos, perfil)
        ]
        for _ in range(LIMITE_DE_ITERACOES):
            mudou = False
            for atribuicao, condicional in atribuicoes:
                procedencias = _procedencias(atribuicao.valor, escopo)
                if not procedencias:
                    continue
                if condicional:
                    procedencias = frozenset(
                        replace(p, condicional=True) for p in procedencias
                    )
                for alvo in atribuicao.alvos:
                    antes = escopo.contaminados.get(alvo, frozenset())
                    depois = antes | procedencias
                    if depois != antes:
                        escopo.contaminados[alvo] = depois
                        mudou = True
            if not mudou:
                break

        escopos.append(escopo)
        for aninhada in aninhadas:
            analisar(aninhada, _nome_do_escopo(aninhada), escopo.contaminados)

    analisar(arquivo.raiz, "<modulo>", {})
    return escopos
