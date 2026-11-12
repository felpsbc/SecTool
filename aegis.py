"""Atalho para rodar o AEGIS sem configurar nada a mao.

    python aegis.py                           modo guiado: arraste a pasta e aperte Enter
                                              (no Windows, basta dar dois cliques no arquivo)
    python aegis.py caminho/do/projeto        analisa um arquivo ou pasta
    python aegis.py caminho --json --saida rel.json   salva o relatorio JSON
    python aegis.py caminho --saida rel.txt           salva o relatorio em texto
    python aegis.py --testar                  valida a ferramenta no corpus rotulado
    python aegis.py --api                     sobe a API HTTP (http://127.0.0.1:8000/docs)

Na primeira execucao cria TOOL/.venv e instala o AEGIS nele (precisa de
internet so para o suporte a JS/TS, Java, PHP e HTML; Python funciona mesmo
se essa parte falhar). Depois disso, cada execucao e direta.
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv
from pathlib import Path
from urllib.parse import unquote, urlparse

RAIZ = Path(__file__).resolve().parent
TOOL = RAIZ / "TOOL"
AMBIENTE = TOOL / ".venv"
MARCA = AMBIENTE / ".aegis-instalado"
# Saida sempre em UTF-8: sem isso, no Windows, acentos viram lixo ao redirecionar.
AMBIENTE_UTF8 = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def python_do_ambiente() -> Path:
    if sys.platform == "win32":
        return AMBIENTE / "Scripts" / "python.exe"
    return AMBIENTE / "bin" / "python"


def preparar(extras: str) -> Path:
    """Cria o ambiente e instala os extras pedidos, uma vez so."""
    python = python_do_ambiente()
    instalados = set(MARCA.read_text().split(",")) if MARCA.exists() else set()
    faltando = set(extras.split(",")) - instalados
    if python.exists() and not faltando:
        return python

    if not python.exists():
        print("[aegis] criando ambiente virtual em TOOL/.venv ...", file=sys.stderr)
        venv.create(AMBIENTE, with_pip=True)

    print(f"[aegis] instalando o AEGIS ({extras}) — so na primeira vez ...", file=sys.stderr)
    pip = [str(python), "-m", "pip", "install", "-q", "--disable-pip-version-check"]
    if subprocess.run([*pip, "-e", f"{TOOL}[{extras}]"]).returncode == 0:
        instalados |= set(extras.split(","))
    elif subprocess.run([*pip, "-e", str(TOOL)]).returncode == 0:
        print(
            "[aegis] aviso: extras nao instalados (sem internet?). Python e configuracao "
            "funcionam; JS/TS, Java, PHP e HTML ficarao como falha de leitura.",
            file=sys.stderr,
        )
    else:
        sys.exit("[aegis] erro: nao consegui instalar o AEGIS. Veja docs/instalacao.md.")
    MARCA.write_text(",".join(sorted(instalados)))
    return python


def limpar_caminho(texto: str) -> Path:
    """Aceita o que o terminal cola ao arrastar uma pasta: aspas, file://, espacos."""
    texto = texto.strip().strip("'\"").strip()
    if texto.startswith("file://"):
        texto = unquote(urlparse(texto).path)
    return Path(texto).expanduser()


def modo_guiado() -> int:
    """Pergunta o caminho em vez de exigir argumentos — pensado para iniciantes."""
    print("=" * 66)
    print(" AEGIS — analise de seguranca do seu codigo (OWASP Top 10)")
    print("=" * 66)
    python = preparar("linguagens")
    exemplo = RAIZ / "docs" / "teste" / "app_vulneravel.py"
    relatorio = RAIZ / "relatorio_aegis.txt"
    while True:
        print()
        print("Arraste para esta janela a PASTA ou o ARQUIVO do seu projeto e aperte Enter.")
        print("  (digite  exemplo  para testar com um app vulneravel, ou so Enter para sair)")
        try:
            resposta = input("> ")
        except (EOFError, KeyboardInterrupt):
            return 0
        if not resposta.strip():
            return 0
        alvo = exemplo if resposta.strip().lower() == "exemplo" else limpar_caminho(resposta)
        if not alvo.exists():
            print(f"Nao encontrei: {alvo}")
            print("Dica: arraste a pasta do Explorador/gerenciador de arquivos para esta janela.")
            continue
        processo = subprocess.run(
            [str(python), "-m", "owaspscan", str(alvo)],
            capture_output=True, env=AMBIENTE_UTF8,
        )
        texto = processo.stdout.decode("utf-8", errors="replace")
        print(texto)
        relatorio.write_text(texto, encoding="utf-8")
        print(f"Relatorio salvo em: {relatorio}")


def main(argumentos: list[str]) -> int:
    if sys.version_info < (3, 11):
        sys.exit(f"[aegis] erro: precisa de Python 3.11 ou mais novo (este e {sys.version.split()[0]}).")
    if not argumentos:
        if not sys.stdin.isatty():
            print(__doc__)
            return 2
        try:
            return modo_guiado()
        except SystemExit as erro:
            # Aberto com dois cliques, a janela fecharia antes de a pessoa ler o erro.
            print(erro)
            input("Aperte Enter para fechar.")
            return 1
    if argumentos[0] in {"-h", "--help", "--ajuda"}:
        print(__doc__)
        return 0

    if argumentos[0] == "--testar":
        python = preparar("linguagens,dev")
        comando = [str(python), "-m", "owaspscan.metricas", "tests/amostras"]
    elif argumentos[0] == "--api":
        python = preparar("linguagens,api")
        comando = [str(python), "-m", "owaspscan.api"]
    else:
        saida = None
        if "--saida" in argumentos:
            # Grava pelo Python, nao pelo ">" do shell: no PowerShell o ">"
            # muda a codificacao e estraga os acentos do relatorio.
            posicao = argumentos.index("--saida")
            if posicao + 1 >= len(argumentos):
                sys.exit("[aegis] erro: informe o arquivo depois de --saida.")
            saida = Path(argumentos[posicao + 1])
            argumentos = argumentos[:posicao] + argumentos[posicao + 2 :]
        python = preparar("linguagens")
        # Caminhos relativos continuam relativos a pasta de onde o usuario chamou.
        comando = [str(python), "-m", "owaspscan", *argumentos]
        if saida is None:
            return subprocess.run(comando, env=AMBIENTE_UTF8).returncode
        with saida.open("wb") as arquivo:
            codigo = subprocess.run(comando, stdout=arquivo, env=AMBIENTE_UTF8).returncode
        print(f"[aegis] relatorio salvo em {saida.resolve()}", file=sys.stderr)
        return codigo
    return subprocess.run(comando, cwd=TOOL, env=AMBIENTE_UTF8).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        raise SystemExit(130)
