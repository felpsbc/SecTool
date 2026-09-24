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
from owaspscan.configuracao import ler_diretorio
from owaspscan.detectores.base import Detector, ordenar_achados
from owaspscan.detectores.autenticacao import (
    DetectorCookieInseguro,
    DetectorExpiracaoDeSessao,
    DetectorHashDeSenhaFraco,
    DetectorJwtSemVerificacao,
    DetectorLoginSemLimite,
    DetectorSenhaEmTextoPuro,
)
from owaspscan.detectores.autorizacao import DetectorAutorizacao
from owaspscan.detectores.credenciais import (
    DetectorCredenciais,
    DetectorCredenciaisEmConfiguracao,
)
from owaspscan.detectores.csrf import DetectorCsrf
from owaspscan.detectores.idor import DetectorIdor
from owaspscan.detectores.open_redirect import DetectorOpenRedirect
from owaspscan.detectores.path_traversal import DetectorPathTraversal
from owaspscan.detectores.sqli import DetectorSqlInjection
from owaspscan.detectores.xss import DetectorXss
from owaspscan.detectores.xxe import DetectorXxe
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo
from owaspscan.motor.taint import analisar_taint

VERSAO = "0.2.0"
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
        DetectorJwtSemVerificacao(catalogo=catalogo),
        DetectorHashDeSenhaFraco(catalogo=catalogo),
        DetectorSenhaEmTextoPuro(catalogo=catalogo),
        DetectorCookieInseguro(catalogo=catalogo),
        DetectorExpiracaoDeSessao(catalogo=catalogo),
        DetectorLoginSemLimite(catalogo=catalogo),
        DetectorCredenciais(catalogo=catalogo),
    )


@dataclass(frozen=True)
class Varredura:
    """Tudo que uma execucao produziu, incluindo o que nao deu certo."""

    raiz: str
    achados: tuple[Achado, ...] = ()
    arquivos_analisados: int = 0
    arquivos_de_configuracao: int = 0
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
    incluir_configuracao: bool = True,
) -> Varredura:
    """Analisa a raiz (arquivo ou diretorio) com todos os detectores.

    Alem do codigo Python, le arquivos de configuracao (.env, YAML, JSON,
    INI, TOML, .properties) em busca de credenciais fixas, a menos que
    `incluir_configuracao` seja False.
    """
    caminho = Path(raiz)
    ativos = detectores if detectores is not None else detectores_padrao(catalogo)
    analisados, falhas = analisar_diretorio(caminho)

    achados: list[Achado] = []
    for arquivo in analisados:
        escopos = analisar_taint(arquivo, catalogo=catalogo)
        for detector in ativos:
            achados.extend(detector.detectar(arquivo, escopos))

    configuracoes = []
    if incluir_configuracao:
        configuracoes, falhas_de_configuracao = ler_diretorio(caminho)
        falhas = [*falhas, *falhas_de_configuracao]
        detector_de_configuracao = DetectorCredenciaisEmConfiguracao()
        for configuracao in configuracoes:
            achados.extend(detector_de_configuracao.detectar(configuracao))

    return Varredura(
        raiz=str(raiz),
        achados=tuple(ordenar_achados(achados)),
        arquivos_analisados=len(analisados),
        arquivos_de_configuracao=len(configuracoes),
        falhas=tuple(falhas),
        momento=momento or datetime.now(),
    )
