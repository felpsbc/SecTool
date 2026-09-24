"""Apoio aos testes: leitura do gabarito embutido nas amostras.

A logica de gabarito mora em `owaspscan.metricas` — avaliar contra corpus
rotulado e funcionalidade da ferramenta, nao detalhe de teste. Aqui ficam
apenas os atalhos usados pelos testes de cada detector.
"""

from __future__ import annotations

from pathlib import Path

from owaspscan.metricas import carregar_gabarito

DIRETORIO_AMOSTRAS = Path(__file__).parent / "amostras"


def linhas_esperadas(caminho: Path, cwe: str) -> list[int]:
    """Linhas marcadas como achado esperado para a CWE."""
    return sorted(
        item.linha
        for item in carregar_gabarito(caminho)
        if item.cwe == cwe and not item.limitacao
    )


def linhas_de_limitacao(caminho: Path) -> list[int]:
    """Linhas marcadas como falso negativo conhecido e aceito."""
    return sorted(
        item.linha for item in carregar_gabarito(caminho) if item.limitacao
    )


def rodar_detector(detector, fonte: str, arquivo: str = "app.py"):
    """Roda um detector sobre codigo em memoria."""
    from owaspscan.analisador import analisar_texto
    from owaspscan.motor.taint import analisar_taint

    analisado = analisar_texto(fonte, arquivo)
    return detector.detectar(analisado, analisar_taint(analisado))


def rodar_detector_em_arquivo(detector, caminho: Path):
    """Roda um detector sobre uma amostra do corpus."""
    from owaspscan.analisador import analisar_arquivo
    from owaspscan.motor.taint import analisar_taint

    analisado = analisar_arquivo(caminho, caminho.parent)
    return detector.detectar(analisado, analisar_taint(analisado))
