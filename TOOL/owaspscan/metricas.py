"""Avaliacao da ferramenta contra um corpus rotulado.

O gabarito mora nas proprias amostras, como comentario na linha do sink:

    cursor.execute("SELECT ... " + ident)   # achado: CWE-89, CWE-639
    cursor.execute(consulta)                # limitacao: CWE-89 fluxo interprocedural

`achado` marca vulnerabilidade que a ferramenta deve encontrar. `limitacao`
marca vulnerabilidade real que sabemos NAO encontrar: conta como falso
negativo, e nao como isencao — declarar a falha nao a transforma em acerto.

A leitura desses marcadores usa expressao regular porque le ROTULOS de um
corpus, nao codigo: a deteccao continua sendo exclusivamente por AST.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from owaspscan.achado import MAPA_CWE_OWASP
from owaspscan.varredura import Varredura, executar

_MARCA_ACHADO = re.compile(r"#\s*achado:\s*([A-Za-z0-9\-,\s]+)")
_MARCA_LIMITACAO = re.compile(r"#\s*limitacao:\s*(CWE-\d+)\s*(.*)")


@dataclass(frozen=True)
class ItemDeGabarito:
    """Uma vulnerabilidade conhecida do corpus."""

    arquivo: str
    linha: int
    cwe: str
    limitacao: str = ""  # motivo, quando e falso negativo conhecido

    @property
    def chave(self) -> tuple[str, int, str]:
        return (self.arquivo, self.linha, self.cwe)


def _cwes_marcadas(texto: str) -> list[str]:
    casamento = _MARCA_ACHADO.search(texto)
    if not casamento:
        return []
    return [
        parte.strip()
        for parte in casamento.group(1).split(",")
        if parte.strip() in MAPA_CWE_OWASP
    ]


def carregar_gabarito(raiz: Path | str) -> list[ItemDeGabarito]:
    """Le os marcadores de gabarito de todos os .py sob a raiz."""
    raiz = Path(raiz)
    base = raiz if raiz.is_dir() else raiz.parent
    arquivos = [raiz] if raiz.is_file() else sorted(raiz.rglob("*.py"))

    itens: list[ItemDeGabarito] = []
    for caminho in arquivos:
        relativo = caminho.relative_to(base).as_posix()
        for numero, linha in enumerate(caminho.read_text().splitlines(), start=1):
            for cwe in _cwes_marcadas(linha):
                itens.append(ItemDeGabarito(relativo, numero, cwe))
            limitacao = _MARCA_LIMITACAO.search(linha)
            if limitacao:
                itens.append(
                    ItemDeGabarito(
                        relativo, numero, limitacao.group(1), limitacao.group(2).strip()
                    )
                )
    return itens


@dataclass(frozen=True)
class Metricas:
    """Contagens e taxas de uma CWE (ou do conjunto)."""

    vp: int = 0
    fp: int = 0
    fn: int = 0
    fn_conhecidos: int = 0

    @property
    def precisao(self) -> float:
        total = self.vp + self.fp
        return self.vp / total if total else 0.0

    @property
    def recall(self) -> float:
        total = self.vp + self.fn
        return self.vp / total if total else 0.0

    @property
    def f1(self) -> float:
        soma = self.precisao + self.recall
        return 2 * self.precisao * self.recall / soma if soma else 0.0


def avaliar(
    raiz: Path | str, varredura: Varredura | None = None
) -> dict[str, Metricas]:
    """Compara os achados da varredura com o gabarito, por CWE e no total."""
    varredura = varredura if varredura is not None else executar(raiz)
    gabarito = carregar_gabarito(raiz)

    esperados = {item.chave for item in gabarito}
    conhecidos = {item.chave for item in gabarito if item.limitacao}
    obtidos = {(a.arquivo, a.linha, a.cwe) for a in varredura.achados}

    cwes = sorted({chave[2] for chave in esperados | obtidos})
    resultado: dict[str, Metricas] = {}
    for cwe in cwes:
        esperados_cwe = {c for c in esperados if c[2] == cwe}
        obtidos_cwe = {c for c in obtidos if c[2] == cwe}
        faltantes = esperados_cwe - obtidos_cwe
        resultado[cwe] = Metricas(
            vp=len(esperados_cwe & obtidos_cwe),
            fp=len(obtidos_cwe - esperados_cwe),
            fn=len(faltantes),
            fn_conhecidos=len(faltantes & conhecidos),
        )

    faltantes = esperados - obtidos
    resultado["geral"] = Metricas(
        vp=len(esperados & obtidos),
        fp=len(obtidos - esperados),
        fn=len(faltantes),
        fn_conhecidos=len(faltantes & conhecidos),
    )
    return resultado


AVISO_DE_ESCOPO = (
    "Corpus proprio, pequeno e construido junto com a ferramenta: estes\n"
    "numeros medem consistencia interna, NAO generalizacao. Comparacao com\n"
    "a literatura exige corpus externo (OWASP Benchmark, PyGoat)."
)


def formatar_tabela(metricas: dict[str, Metricas], varredura: Varredura) -> str:
    """Tabela de precisao/recall por CWE, com o denominador da varredura."""
    linhas = [
        "=" * 74,
        " OWASP-Scan — avaliacao contra corpus rotulado",
        "=" * 74,
        f" Arquivos analisados : {varredura.arquivos_analisados}",
        f" Arquivos com falha  : {len(varredura.falhas)}",
        "",
        f" {'CWE':<10}{'VP':>5}{'FP':>5}{'FN':>5}{'FN conh.':>10}"
        f"{'Precisao':>11}{'Recall':>9}{'F1':>8}",
        " " + "-" * 71,
    ]
    for nome in [c for c in metricas if c != "geral"] + ["geral"]:
        m = metricas[nome]
        linhas.append(
            f" {nome:<10}{m.vp:>5}{m.fp:>5}{m.fn:>5}{m.fn_conhecidos:>10}"
            f"{m.precisao:>11.2f}{m.recall:>9.2f}{m.f1:>8.2f}"
        )
    linhas += ["", " " + AVISO_DE_ESCOPO.replace("\n", "\n "), "=" * 74]
    return "\n".join(linhas)


def main(argv: list[str] | None = None) -> int:
    argumentos = argv if argv is not None else sys.argv[1:]
    raiz = Path(argumentos[0]) if argumentos else Path("tests/amostras")
    if not raiz.exists():
        print(f"erro: caminho nao encontrado: {raiz}", file=sys.stderr)
        return 2
    varredura = executar(raiz)
    print(formatar_tabela(avaliar(raiz, varredura), varredura))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
