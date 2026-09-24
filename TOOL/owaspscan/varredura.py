"""Orquestracao: varre uma raiz, roda os detectores e junta o resultado.

Separado do relatorio de proposito: aqui acontece o I/O e a execucao dos
detectores; `relatorio.py` so formata o que sai daqui.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from owaspscan.achado import Achado
from owaspscan.analisador import FalhaDeLeitura, analisar_diretorio
from owaspscan.detectores.base import Detector, ordenar_achados
from owaspscan.detectores.autorizacao import DetectorAutorizacao
from owaspscan.detectores.csrf import DetectorCsrf
from owaspscan.detectores.idor import DetectorIdor
from owaspscan.detectores.open_redirect import DetectorOpenRedirect
from owaspscan.detectores.path_traversal import DetectorPathTraversal
from owaspscan.detectores.sqli import DetectorSqlInjection
from owaspscan.detectores.xss import DetectorXss
from owaspscan.detectores.xxe import DetectorXxe
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo
from owaspscan.motor.taint import analisar_taint

VERSAO = "0.1.0"
CONFIANCA_DE_CANDIDATO = "baixa"


def detectores_padrao(catalogo: Catalogo = CATALOGO_PADRAO) -> tuple[Detector, ...]:
    """Os detectores do escopo atual, na ordem do relatorio."""
    return (
        DetectorSqlInjection(catalogo=catalogo),
        DetectorXss(catalogo=catalogo),
        DetectorIdor(catalogo=catalogo),
        DetectorXxe(catalogo=catalogo),
        DetectorPathTraversal(catalogo=catalogo),
        DetectorOpenRedirect(catalogo=catalogo),
        DetectorCsrf(catalogo=catalogo),
        DetectorAutorizacao(catalogo=catalogo),
    )


@dataclass(frozen=True)
class Varredura:
    """Tudo que uma execucao produziu, incluindo o que nao deu certo."""

    raiz: str
    achados: tuple[Achado, ...] = ()
    arquivos_analisados: int = 0
    falhas: tuple[FalhaDeLeitura, ...] = ()
    momento: datetime = field(default_factory=datetime.now)
    versao: str = VERSAO

    @property
    def confirmados(self) -> tuple[Achado, ...]:
        """Achados sustentados por uma cadeia de taint observada."""
        return tuple(a for a in self.achados if a.confianca != CONFIANCA_DE_CANDIDATO)

    @property
    def candidatos(self) -> tuple[Achado, ...]:
        """Achados heuristicos, que exigem revisao manual."""
        return tuple(a for a in self.achados if a.confianca == CONFIANCA_DE_CANDIDATO)

    @property
    def tem_severidade_alta(self) -> bool:
        return any(a.severidade == "alta" for a in self.achados)


def executar(
    raiz: Path | str,
    detectores: tuple[Detector, ...] | None = None,
    catalogo: Catalogo = CATALOGO_PADRAO,
    momento: datetime | None = None,
) -> Varredura:
    """Analisa a raiz (arquivo ou diretorio) com todos os detectores."""
    caminho = Path(raiz)
    ativos = detectores if detectores is not None else detectores_padrao(catalogo)
    analisados, falhas = analisar_diretorio(caminho)

    achados: list[Achado] = []
    for arquivo in analisados:
        escopos = analisar_taint(arquivo, catalogo=catalogo)
        for detector in ativos:
            achados.extend(detector.detectar(arquivo, escopos))

    return Varredura(
        raiz=str(raiz),
        achados=tuple(ordenar_achados(achados)),
        arquivos_analisados=len(analisados),
        falhas=tuple(falhas),
        momento=momento or datetime.now(),
    )
