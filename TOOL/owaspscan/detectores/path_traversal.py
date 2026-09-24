"""Detector de Path Traversal (CWE-22 -> A01:2021 Broken Access Control).

Reporta quando dado de fonte nao confiavel alcanca um caminho de arquivo:
`open`, `send_file`, `os.remove`, `shutil.*`, metodos de `pathlib` sobre
caminho contaminado e `arquivo.save(destino)`.

Duas defesas removem o achado:

1. **Sanitizacao do nome** — `secure_filename`, `safe_join`, `basename` e
   casts, conforme o catalogo (cada um declara que neutraliza CWE-22).
2. **Guarda de confinamento** — o caminho canonicalizado (`realpath`,
   `abspath`, `normpath`, `resolve`) e comparado com a base num `if` ou
   `assert` (`startswith`, `is_relative_to`, `commonpath`). Comparar sem
   canonicalizar NAO conta: `"/base/../etc".startswith("/base")` e True.

Limitacao declarada: a guarda e verificada de forma insensivel a fluxo —
basta existir no escopo; o motor nao confirma que o ramo de falha aborta.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from owaspscan.achado import Achado, criar_achado
from owaspscan.analisador import ArquivoAnalisado
from owaspscan.detectores.comum import (
    argumentos_do_sink,
    casar_sink,
    nomes_contaminados_em,
    testes_de_condicao,
)
from owaspscan.motor.catalogo import (
    CANONICALIZADORES_DE_CAMINHO,
    CATALOGO_PADRAO,
    GUARDAS_DE_CAMINHO,
    METODOS_DE_ARQUIVO_NO_ARGUMENTO,
    METODOS_DE_ARQUIVO_NO_RECEPTOR,
    SINKS_DE_CAMINHO,
    Catalogo,
)
from owaspscan.motor.confianca import (
    confianca_para,
    justificativa,
    procedencias_relevantes,
)
from owaspscan.motor.estrutura import mapa_de_importacoes
from owaspscan.motor.taint import Escopo, Procedencia, nos_do_escopo

RECOMENDACAO = (
    "Nunca use dado da requisicao como caminho. Para nomes de arquivo, aplique "
    "werkzeug.utils.secure_filename; para servir arquivos, use "
    "send_from_directory(BASE, nome) ou safe_join. Se precisar montar o "
    "caminho, canonicalize e confine: destino = os.path.realpath(os.path.join"
    "(BASE, nome)); if not destino.startswith(BASE + os.sep): abort(400)."
)


def _ultimo_nome(func: ast.AST) -> str | None:
    """Nome chamado, inclusive em metodo sobre expressao: `(a / b).resolve`."""
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _contem_canonicalizacao(escopo: Escopo, expressao: ast.AST, profundidade: int = 2) -> bool:
    """A expressao (ou a atribuicao do nome) passa por realpath/abspath/...?"""
    for no in ast.walk(expressao):
        if isinstance(no, ast.Call) and _ultimo_nome(no.func) in CANONICALIZADORES_DE_CAMINHO:
            return True
        if profundidade > 0 and isinstance(no, ast.Name):
            for valor in escopo.atribuicoes.get(no.id, ()):
                if _contem_canonicalizacao(escopo, valor, profundidade - 1):
                    return True
    return False


def nomes_confinados(escopo: Escopo) -> frozenset[str]:
    """Nomes contaminados que passam por uma guarda de confinamento."""
    confinados: set[str] = set()
    for teste in testes_de_condicao(escopo):
        for no in ast.walk(teste):
            if not isinstance(no, ast.Call):
                continue
            func = no.func
            if isinstance(func, ast.Attribute) and func.attr in {
                "startswith",
                "is_relative_to",
            }:
                verificado: list[ast.AST] = [func.value]
            elif _ultimo_nome(func) in GUARDAS_DE_CAMINHO:
                verificado = list(no.args)
            else:
                continue
            for expressao in verificado:
                if _contem_canonicalizacao(escopo, expressao):
                    confinados |= nomes_contaminados_em(escopo, expressao)
                    # O nome confinado tambem protege o que o compoe:
                    # destino = realpath(join(BASE, nome)) confina `nome`.
                    for nome in nomes_contaminados_em(escopo, expressao):
                        for valor in escopo.atribuicoes.get(nome, ()):
                            confinados |= nomes_contaminados_em(escopo, valor)
    return frozenset(confinados)


@dataclass(frozen=True)
class DetectorPathTraversal:
    """Detector de CWE-22 sobre operacoes de arquivo."""

    catalogo: Catalogo = CATALOGO_PADRAO
    nome: str = "Path Traversal"
    cwe: str = "CWE-22"

    def detectar(
        self, arquivo: ArquivoAnalisado, escopos: list[Escopo]
    ) -> list[Achado]:
        importacoes = mapa_de_importacoes(arquivo.arvore)
        achados: list[Achado] = []
        for escopo in escopos:
            confinados = nomes_confinados(escopo)
            for no in nos_do_escopo(escopo):
                if not isinstance(no, ast.Call):
                    continue
                for expressao, descricao in self._caminhos_do_sink(no, importacoes):
                    procedencias = procedencias_relevantes(
                        escopo.procedencias_da_expressao(expressao),
                        self.cwe,
                        self.catalogo,
                    )
                    if not procedencias:
                        continue
                    usados = nomes_contaminados_em(escopo, expressao)
                    if usados and usados <= confinados:
                        continue
                    achados.append(self._montar(arquivo, no, procedencias, descricao))
                    break  # um achado por chamada
        return achados

    def _caminhos_do_sink(
        self, no: ast.Call, importacoes: dict[str, str]
    ) -> list[tuple[ast.AST, str]]:
        sink = casar_sink(no, SINKS_DE_CAMINHO, importacoes)
        if sink is not None:
            return [(arg, sink.descricao) for arg in argumentos_do_sink(no, sink)]
        if isinstance(no.func, ast.Attribute):
            metodo = no.func.attr
            if metodo in METODOS_DE_ARQUIVO_NO_RECEPTOR:
                return [(no.func.value, f".{metodo}() de pathlib")]
            if metodo in METODOS_DE_ARQUIVO_NO_ARGUMENTO and no.args:
                return [(no.args[0], f".{metodo}(destino)")]
        return []

    def _montar(
        self,
        arquivo: ArquivoAnalisado,
        no: ast.AST,
        procedencias: frozenset[Procedencia],
        sink: str,
    ) -> Achado:
        fontes = ", ".join(sorted({p.fonte for p in procedencias}))
        return criar_achado(
            arquivo=arquivo.arquivo,
            linha=arquivo.linha_de(no),
            cwe=self.cwe,
            severidade="alta",
            confianca=confianca_para(procedencias),
            trecho=arquivo.trecho_de(no),
            descricao=(
                f"Dado nao confiavel vindo de {fontes} compoe o caminho usado "
                f"em {sink} sem sanitizacao nem confinamento a um diretorio base, "
                "permitindo ler ou escrever fora dele com '../'."
                + justificativa(procedencias)
            ),
            recomendacao=RECOMENDACAO,
        )
