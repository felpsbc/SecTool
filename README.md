# AEGIS-CODE

**Descubra se o seu código tem vulnerabilidades de segurança antes de colocá-lo em produção.**

O AEGIS é uma ferramenta de análise estática de segurança (SAST): ele lê o seu código, procura falhas do **OWASP Top 10:2021** (SQL Injection, XSS, senhas no código, rotas sem autenticação…) e explica **onde** está cada problema e **como corrigir**. O código analisado **nunca é executado** — o AEGIS só lê a estrutura dele (AST e taint tracking).

Analisa **Python (Flask/Django), JavaScript/TypeScript, Java, PHP, HTML** e arquivos de configuração (`.env`, YAML, JSON, INI, TOML, `.properties`).

[![Abrir no Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/felpsbc/SecTool/blob/main/AEGIS.ipynb)

Repositório: <https://github.com/felpsbc/SecTool> · Site de demonstração: <https://aegisscan-zeta.vercel.app/>

> **Sobre o site:** ele apresenta a interface do AEGIS e faz uma análise **simplificada** no próprio navegador; ele **não** usa o motor `owaspscan` nem a API (detalhes em [`docs/deploy.md`](docs/deploy.md#o-site-publicado-é-uma-demonstração-do-produto-não-um-cliente-da-api)). Para o resultado completo — o que este README ensina — use o **Colab** ou o **`aegis.py`**.

## Identificação do repositório

| Campo | Informação |
| --- | --- |
| Instituição | CEUB |
| Organização no GitHub | CampusCEUB |
| Professor(a) responsável pela criação: | Professor Lucas Rodrigues - 128050 |
| Equipe | Felipe Barcelos de Carvalho, Lucas de Salles Almeida Moura, João Marcelo Guimarães Dourado, Marcos Vinícius Rocha |
| IDProjeto | 20260229 |

## Sumário

1. [Escolha como usar](#1-escolha-como-usar)
2. [No navegador, sem instalar nada (Google Colab)](#2-no-navegador-sem-instalar-nada-google-colab)
3. [**Windows** — passo a passo](#3-windows--passo-a-passo)
4. [**Linux** (e macOS) — passo a passo](#4-linux-e-macos--passo-a-passo)
5. [Como ler o relatório](#5-como-ler-o-relatório)
6. [Problemas comuns (Windows e Linux)](#6-problemas-comuns)
7. [Uso avançado (CLI, JSON, API, site, CI/CD, testes)](#7-uso-avançado)
8. [O que o AEGIS detecta](#8-o-que-o-aegis-detecta)
9. [Sobre o projeto (problema, arquitetura, documentação)](#9-sobre-o-projeto)

---

## 1. Escolha como usar

| Seu caso | Siga | Precisa instalar? |
| --- | --- | --- |
| Quero testar rápido, sem mexer no meu computador | **[2. Google Colab](#2-no-navegador-sem-instalar-nada-google-colab)** | Nada (só uma conta Google) |
| Uso **Windows** (10 ou 11) | **[3. Windows](#3-windows--passo-a-passo)** | Só o Python 3.11+ |
| Uso **Linux** (Ubuntu, Debian, Mint, Fedora, Arch…) ou **macOS** | **[4. Linux](#4-linux-e-macos--passo-a-passo)** | Só o Python 3.11+ |
| Quero integrar em pipeline, script ou outro sistema | **[7. Uso avançado](#7-uso-avançado)** | Python 3.11+ (e Node.js para o site) |
| Só quero conhecer a interface | [Site de demonstração](https://aegisscan-zeta.vercel.app/) (análise simplificada, não é o motor completo) | Nada |

Todos os caminhos têm um passo **“validar a ferramenta”**: o AEGIS roda em códigos de exemplo com vulnerabilidades conhecidas e mostra quantas encontrou. É a forma mais rápida de confirmar que a ferramenta funciona antes de confiar nela para o seu projeto.

No computador, tudo se resume a **um único arquivo**, o `aegis.py`: na primeira execução ele cria um ambiente isolado dentro da própria pasta do AEGIS (`TOOL/.venv`) e instala o que precisa; nada é instalado no resto do sistema.

---

## 2. No navegador, sem instalar nada (Google Colab)

Funciona em qualquer sistema (Windows, Linux, macOS, Chromebook). O arquivo [`AEGIS.ipynb`](AEGIS.ipynb) é um notebook pronto: instala o AEGIS numa máquina temporária do Google, valida a ferramenta e analisa o seu projeto.

1. Clique no botão **Abrir no Colab** no topo desta página (ou abra <https://colab.research.google.com>, menu **Arquivo → Abrir notebook → GitHub**, e cole o endereço deste repositório).
2. Faça login com sua conta Google, se pedido.
3. Na seção **3. Analisar o seu projeto**, escolha a origem no formulário:
   - `github` — cole o link do repositório do seu projeto (repositório **privado**? salve um token do GitHub no Colab em 🔑 **Secrets** com o nome `GITHUB_TOKEN`);
   - `zip` — envie um `.zip` com o seu projeto (será aberto um botão de upload);
   - `pasta_local` — caminho de uma pasta (por exemplo, do Google Drive montado).
4. Menu **Ambiente de execução → Executar tudo** (ou `Ctrl+F9`). Aguarde ~1 minuto.
5. Role até o final: você verá as métricas de validação, a tabela de achados, a explicação e a correção recomendada para cada achado e um botão para baixar o relatório em JSON.

> O notebook também funciona em Jupyter/VS Code no seu computador: abra `AEGIS.ipynb` de dentro do repositório baixado e execute as células.

---

## 3. Windows — passo a passo

Para Windows 10 e 11. Os comandos usam o **Prompt de Comando** (`cmd`); no PowerShell eles funcionam igual.

### W1 — Instalar o Python

1. Abra o menu Iniciar, digite `cmd` e abra o **Prompt de Comando**.
2. Verifique se o Python já está instalado:

   ```bat
   py --version
   ```

   Se aparecer `Python 3.11` ou maior (3.12, 3.13…), pule para o passo W2.
3. Se não, instale de **uma** das formas:
   - **Site oficial (recomendado):** baixe em <https://www.python.org/downloads/windows/>. Na primeira tela do instalador, **marque “Add python.exe to PATH”** e clique em *Install Now*.
   - **Pelo terminal:** `winget install Python.Python.3.12`
4. **Feche e abra de novo** o Prompt de Comando e repita `py --version`.

> Use `py` (o lançador do Python para Windows) em vez de `python`: ele evita que o Windows abra a Microsoft Store no lugar do Python.

### W2 — Baixar o AEGIS

Escolha **uma** das formas:

- **Sem Git (mais simples):** nesta página do GitHub, clique no botão verde **`<> Code` → Download ZIP**. Abra a pasta *Downloads*, clique com o botão direito no ZIP → **Extrair tudo…** → *Extrair*. Você terá uma pasta `SecTool-main`.
- **Com Git** (instale com `winget install Git.Git` se não tiver):

  ```bat
  cd %USERPROFILE%\Documents
  git clone https://github.com/felpsbc/SecTool.git
  ```

### W3 — Abrir o terminal na pasta do AEGIS

A pasta certa é a que contém o arquivo `aegis.py`.

- **Jeito mais fácil:** abra essa pasta no Explorador de Arquivos, clique na **barra de endereço**, apague o que estiver escrito, digite `cmd` e aperte **Enter**. O Prompt de Comando abre já dentro da pasta.
- **Pelo terminal:** `cd` + caminho da pasta, por exemplo:

  ```bat
  cd %USERPROFILE%\Downloads\SecTool-main\SecTool-main
  ```

Confira com `dir`: o arquivo `aegis.py` deve aparecer na lista.

> O ZIP às vezes extrai uma pasta dentro de outra com o mesmo nome (`SecTool-main\SecTool-main`). Entre até a que tem o `aegis.py`.

### W4 — Validar que a ferramenta funciona

```bat
py aegis.py --testar
```

Na **primeira vez** leva cerca de 1 minuto e precisa de internet (cria o ambiente e instala o AEGIS). Nas próximas, é instantâneo. Ao final aparece uma tabela comparando o que o AEGIS encontrou com o gabarito; a linha `geral` deve mostrar algo como **Precisão 1.00 / Recall 0.97** — nenhum alarme falso e quase todas as falhas plantadas encontradas.

Veja um relatório de verdade analisando o app propositalmente vulnerável que vem no repositório:

```bat
py aegis.py docs\teste\app_vulneravel.py
```

### W5 — Analisar o SEU projeto

```bat
py aegis.py C:\Users\seu-nome\projetos\minha-api
```

- **Dica:** digite `py aegis.py ` (com espaço no final) e **arraste a pasta do projeto** do Explorador para dentro do terminal — o caminho é colado sozinho.
- **Caminho com espaços** precisa de aspas: `py aegis.py "C:\Users\Joao Silva\Meus Projetos\api"`.
- Pastas como `node_modules`, `.venv` e `.git` são ignoradas automaticamente.

Para **salvar o relatório** num arquivo (abre no Bloco de Notas ou no navegador):

```bat
py aegis.py C:\projetos\minha-api --saida relatorio.txt
py aegis.py C:\projetos\minha-api --json --saida relatorio.json
```

> Prefira `--saida` a `> relatorio.txt`: no PowerShell, o `>` muda a codificação do arquivo e estraga os acentos.

**Resumo para Windows (quem já sabe o caminho):**

```bat
git clone https://github.com/felpsbc/SecTool.git && cd SecTool
py aegis.py --testar
py aegis.py C:\caminho\do\projeto
```

---

## 4. Linux (e macOS) — passo a passo

Para Ubuntu, Debian, Linux Mint, Fedora, Arch e derivados. No **macOS** os comandos são os mesmos; veja a observação no passo L1.

### L1 — Instalar o Python

Abra um terminal (`Ctrl+Alt+T` na maioria das distribuições) e verifique:

```bash
python3 --version
```

Se aparecer `Python 3.11` ou maior, ainda instale o pacote de ambientes virtuais da sua distribuição (abaixo) e siga para o L2. Caso contrário, instale o Python completo:

| Distribuição | Comando |
| --- | --- |
| **Ubuntu 24.04+, Debian 12+, Mint 22+** | `sudo apt update && sudo apt install -y python3 python3-venv git` |
| **Ubuntu 22.04 / Mint 21** (vem com Python 3.10, antigo demais) | `sudo add-apt-repository -y ppa:deadsnakes/ppa && sudo apt update && sudo apt install -y python3.12 python3.12-venv git` — depois use **`python3.12`** no lugar de `python3` em todos os comandos |
| **Fedora** | `sudo dnf install -y python3 git` |
| **Arch / Manjaro** | `sudo pacman -S --needed python git` |
| **macOS** | Instale pelo site <https://www.python.org/downloads/macos/> ou com `brew install python@3.12 git` |

### L2 — Baixar o AEGIS

**Com Git (recomendado):**

```bash
cd ~
git clone https://github.com/felpsbc/SecTool.git
```

**Sem Git:** no GitHub, clique em **`<> Code` → Download ZIP** e extraia:

```bash
cd ~/Downloads
unzip SecTool-main.zip          # se faltar: sudo apt install unzip
```

### L3 — Entrar na pasta do AEGIS

```bash
cd ~/SecTool                  # ou: cd ~/Downloads/SecTool-main
ls                            # o arquivo aegis.py deve aparecer
```

Atalho pela interface gráfica: clique com o botão direito dentro da pasta → **Abrir no terminal**.

### L4 — Validar que a ferramenta funciona

```bash
python3 aegis.py --testar
```

Na **primeira vez** leva cerca de 1 minuto e precisa de internet (cria o ambiente e instala o AEGIS). Nas próximas, é instantâneo. A linha `geral` da tabela final deve mostrar algo como **Precisão 1.00 / Recall 0.97**.

Veja um relatório de verdade:

```bash
python3 aegis.py docs/teste/app_vulneravel.py
```

### L5 — Analisar o SEU projeto

```bash
python3 aegis.py ~/projetos/minha-api
```

- **Dica:** digite `python3 aegis.py ` (com espaço) e **arraste a pasta** do gerenciador de arquivos para o terminal.
- **Caminho com espaços** precisa de aspas: `python3 aegis.py "$HOME/Meus Projetos/api"` (dentro de aspas, use `$HOME` em vez de `~`).
- Pastas como `node_modules`, `.venv` e `.git` são ignoradas automaticamente.

Para **salvar o relatório**:

```bash
python3 aegis.py ~/projetos/minha-api --saida relatorio.txt
python3 aegis.py ~/projetos/minha-api --json --saida relatorio.json
# ou com redirecionamento, se preferir:
python3 aegis.py ~/projetos/minha-api --json > relatorio.json
```

**Resumo para Linux/macOS (quem já sabe o caminho):**

```bash
git clone https://github.com/felpsbc/SecTool.git && cd SecTool
python3 aegis.py --testar
python3 aegis.py caminho/do/projeto
```

---

## 5. Como ler o relatório

O relatório começa com um **resumo executivo** e depois lista cada achado assim:

```text
  [ALTA / confianca alta] CWE-89 SQL Injection
    app_vulneravel.py:43  (A03:2021 Injection)
    > cursor.execute("SELECT * FROM usuarios WHERE id = " + ident)
    Dado nao confiavel vindo de request.args alcanca a string SQL de
    cursor.execute (DB-API) sem parametrizacao, permitindo alterar a
    estrutura da query.
```

| Campo | Significado |
| --- | --- |
| `ALTA / MEDIA / BAIXA` | **Severidade**: o estrago possível se a falha for explorada. Comece corrigindo as altas. |
| `confianca alta/media/baixa` | **Quão certo** o AEGIS está. Achados de confiança baixa são *candidatos* e precisam de revisão humana. |
| `CWE-89` | Identificador internacional do tipo de falha ([cwe.mitre.org](https://cwe.mitre.org)). |
| `A03:2021 Injection` | Categoria correspondente no OWASP Top 10:2021. |
| `arquivo:linha` | Onde está o problema. |
| `>` | O trecho de código (segredos aparecem mascarados, ex. `"ch***"`). |
| Texto final | Por que é perigoso. |

**Como corrigir:** o final do relatório em texto traz a seção **RECOMENDACOES POR TIPO**, com a correção para cada tipo de falha encontrada. No JSON (`--json`), cada achado tem o campo `recomendacao`; no notebook, a célula *Como corrigir cada achado* mostra problema e correção lado a lado.

Os achados vêm em dois blocos:

- **Rastreados por taint** — o AEGIS seguiu o dado desde a entrada do usuário (ex.: `request.args`) até o ponto perigoso (ex.: a query SQL) e viu que não havia proteção no caminho.
- **Candidatos heurísticos** — padrões suspeitos (como possível IDOR) que **não são certeza**; revise manualmente.

**Código de saída** (útil em scripts e CI): `0` = nenhum achado de severidade alta · `1` = há achado de severidade alta · `2` = erro de uso (ex.: caminho inexistente). Candidatos heurísticos nunca quebram o build.

> **“Nenhum achado” não significa “código seguro”.** O AEGIS encontra uma lista definida de falhas (veja a [seção 8](#8-o-que-o-aegis-detecta)); falhas de lógica de negócio, dependências vulneráveis e problemas de infraestrutura estão fora do escopo.

---

## 6. Problemas comuns

### Em qualquer sistema

| Sintoma | Solução |
| --- | --- |
| `can't open file 'aegis.py'` / `No such file or directory` | O terminal não está na pasta do AEGIS. Refaça o passo [W3](#w3--abrir-o-terminal-na-pasta-do-aegis) (Windows) ou [L3](#l3--entrar-na-pasta-do-aegis) (Linux). |
| `precisa de Python 3.11 ou mais novo` | Instale uma versão recente: [W1](#w1--instalar-o-python) (Windows) ou [L1](#l1--instalar-o-python) (Linux). |
| `erro: caminho nao encontrado` | Confira o caminho do projeto; se tiver espaços, coloque entre aspas. |
| `extras nao instalados (sem internet?)` | Python e configuração funcionam mesmo assim. Para JS/TS, Java, PHP e HTML: conecte-se à internet, apague a pasta `TOOL/.venv` e rode de novo. |
| Arquivos aparecem em “falha de leitura” | Arquivo com erro de sintaxe ou linguagem sem suporte instalado; o restante é analisado normalmente. |
| Quero reinstalar do zero | Apague a pasta `TOOL/.venv` — ela é recriada na próxima execução. |
| Colab: `Falha ao clonar` o seu projeto | Confira o link. Se o seu repositório for privado, salve um token no Colab em 🔑 **Secrets** com o nome `GITHUB_TOKEN`. |

### Windows

| Sintoma | Solução |
| --- | --- |
| `'py' não é reconhecido como um comando interno` | O Python não está instalado ou o terminal foi aberto antes da instalação. Instale pelo site oficial ([W1](#w1--instalar-o-python)) e abra um **novo** Prompt de Comando. |
| `python` abre a Microsoft Store | Use `py` em vez de `python`. Ou desative em *Configurações → Aplicativos → Configurações avançadas de aplicativos → Aliases de execução de aplicativo* os itens “python.exe” e “python3.exe”. |
| Erro de permissão / “Acesso negado” ao criar `TOOL\.venv` | Não deixe o AEGIS dentro de `C:\Program Files`. Mova a pasta para `Documentos` ou `Downloads`. |
| Antivírus bloqueia ou demora na primeira execução | É a criação do ambiente Python. Aguarde ou libere a pasta do AEGIS no antivírus. |
| Acentos estranhos no relatório salvo | Use `--saida relatorio.txt` em vez de `> relatorio.txt`. |
| `git` não é reconhecido | Use o Download ZIP ([W2](#w2--baixar-o-aegis)) ou instale com `winget install Git.Git`. |

### Linux

| Sintoma | Solução |
| --- | --- |
| `ensurepip is not available` / `No module named venv` | Falta o pacote de ambientes virtuais: `sudo apt install python3-venv` (ou `python3.12-venv`, conforme sua versão). Depois apague `TOOL/.venv` e rode de novo. |
| `python3 --version` mostra 3.10 ou menor (Ubuntu 22.04) | Instale o 3.12 pelo PPA deadsnakes ([L1](#l1--instalar-o-python)) e use `python3.12 aegis.py …`. |
| `python: command not found` | No Linux o comando é `python3`. |
| `Permission denied` | Não rode com `sudo`. Se a pasta foi criada com `sudo`, corrija o dono: `sudo chown -R $USER: ~/SecTool`. |
| `externally-managed-environment` | Só acontece se você rodar `pip install` fora do `aegis.py`. O `aegis.py` instala dentro de `TOOL/.venv`, sem esse problema. |

Mais detalhes: [`docs/instalacao.md`](docs/instalacao.md).

---

## 7. Uso avançado

### Atalho `aegis.py` — todas as opções

| Comando (Linux: `python3`, Windows: `py`) | O que faz |
| --- | --- |
| `aegis.py CAMINHO` | Analisa um arquivo ou pasta e mostra o relatório em texto |
| `aegis.py CAMINHO --json` | JSON no stdout, resumo em texto no stderr |
| `aegis.py CAMINHO [--json] --saida ARQUIVO` | Salva o relatório em ARQUIVO (UTF-8) |
| `aegis.py --testar` | Precisão/recall/F1 no corpus rotulado |
| `aegis.py --api` | Sobe a API HTTP em `http://127.0.0.1:8000/docs` |

### Instalação manual (sem o atalho)

**Linux / macOS:**

```bash
cd TOOL
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[linguagens,dev]"
.venv/bin/owasp-scan caminho/do/projeto
```

**Windows (Prompt de Comando):**

```bat
cd TOOL
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[linguagens,dev]"
.venv\Scripts\owasp-scan caminho\do\projeto
```

| Extra | Para quê |
| --- | --- |
| *(nenhum)* | Núcleo: Python + configuração. **Somente stdlib**, zero dependências. |
| `linguagens` | tree-sitter para JS/TS, Java, PHP e HTML |
| `api` | FastAPI + Uvicorn para a API HTTP |
| `dev` | pytest + httpx |

### CLI com filtros

**Linux / macOS** (com `jq`):

```bash
.venv/bin/owasp-scan app.py --json | jq '.resumo'
.venv/bin/owasp-scan app.py --json | jq '.achados[] | select(.severidade=="alta")'
```

**Windows (PowerShell):**

```powershell
$r = .\.venv\Scripts\owasp-scan app.py --json | Out-String | ConvertFrom-Json
$r.resumo
$r.achados | Where-Object severidade -eq "alta" | Format-Table cwe, arquivo, linha
```

### API HTTP

```bash
python3 aegis.py --api          # Windows: py aegis.py --api
# Swagger: http://127.0.0.1:8000/docs     Saúde: http://127.0.0.1:8000/saude
curl -F "arquivos=@app.py" http://127.0.0.1:8000/analisar     # Windows: curl.exe -F ...
```

Variáveis opcionais: `OWASPSCAN_HOST` (padrão `127.0.0.1`), `OWASPSCAN_PORTA` (`8000`), `OWASPSCAN_ORIGENS` (CORS, padrão `*`) — no Linux `export OWASPSCAN_PORTA=9000`, no Windows `set OWASPSCAN_PORTA=9000` (cmd) ou `$env:OWASPSCAN_PORTA=9000` (PowerShell). Contrato completo: [`docs/API.md`](docs/API.md) · configurações: [`docs/configuracao.md`](docs/configuracao.md). Uploads são destruídos ao fim de cada requisição; não há banco de dados.

### Site (frontend)

Requer **Node.js ^20.19.0 ou ≥22.12.0** (Windows: `winget install OpenJS.NodeJS.LTS`; Linux: <https://nodejs.org> ou `nvm`). Com a API rodando em outro terminal:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 — /api é repassado para :8000
```

O frontend é o mesmo do [site de demonstração](https://aegisscan-zeta.vercel.app/): a análise que ele mostra é feita no navegador e **não** chama a API — `frontend/src/api.js` existe, mas não está ligado ao `App.jsx`. Por isso o `docs/teste/ROTEIRO_DE_TESTE.md` não corresponde mais ao site. Estado atual e como reconectar o site à API: [`docs/deploy.md`](docs/deploy.md).

### CI/CD (bloquear merge com falha alta)

Exemplo de GitHub Actions no **seu** projeto (funciona em `ubuntu-latest` e `windows-latest`):

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install "owaspscan[linguagens] @ git+https://github.com/felpsbc/SecTool.git#subdirectory=TOOL"
- run: owasp-scan . --json > aegis.json   # exit 1 se houver achado de severidade alta
```

### Testes e métricas

```bash
cd TOOL
.venv/bin/python -m pytest -v                          # Windows: .venv\Scripts\python -m pytest -v
.venv/bin/python -m owaspscan.metricas tests/amostras  # = aegis.py --testar
```

O corpus de avaliação fica em `TOOL/tests/amostras/`, com gabarito embutido em comentários (`# achado: CWE-89` / `# limitacao: CWE-89 motivo`). Resultado atual: **precisão 1.00 / recall 0.97 / F1 0.98** — corpus próprio, mede consistência interna, **não** generalização.

---

## 8. O que o AEGIS detecta

16 CWEs mapeadas ao OWASP Top 10:2021:

| OWASP | Falhas |
| --- | --- |
| A01 Broken Access Control | IDOR (candidatos, CWE-639), Path Traversal (CWE-22), Open Redirect (CWE-601), CSRF (CWE-352), rota sem autorização (CWE-862) |
| A02 Cryptographic Failures | Hash fraco de senha (CWE-916) |
| A03 Injection | SQL Injection (CWE-89), Cross-Site Scripting (CWE-79) |
| A04 Insecure Design | Senha armazenada em texto puro (CWE-256) |
| A05 Security Misconfiguration | XXE (CWE-611), cookie sem `Secure` (CWE-614) ou sem `HttpOnly` (CWE-1004) |
| A07 Identification and Authentication Failures | JWT sem verificação (CWE-287), login sem limite de tentativas (CWE-307), sessão longa demais (CWE-613), credenciais fixas no código **e** em configuração (CWE-798) |

Cobertura por linguagem, técnicas e limitações conhecidas: [`TOOL/README.md`](TOOL/README.md#cobertura).

---

## 9. Sobre o projeto

### Problema e objetivo

Estudos indicam que 40–45% do código gerado por IA contém vulnerabilidades conhecidas (Pearce, 2022; Veracode, 2025), e esse código costuma ir para produção sem revisão (Perry, 2023). O objetivo do AEGIS é ser uma barreira entre o código gerado por IA e o ambiente de produção: detectar essas falhas antes do deploy, com priorização por severidade/confiança e remediação educativa.

### Tecnologias

| Parte | Stack |
| --- | --- |
| Motor (`TOOL/`) | Python ≥3.11, **somente stdlib** no núcleo (`ast`, `dataclasses`, `pathlib`) |
| Outras linguagens | tree-sitter (extra opcional `[linguagens]`) |
| API HTTP | FastAPI + Uvicorn (extra opcional `[api]`) |
| Testes | pytest (+ httpx para a API) |
| Frontend (`frontend/`) | React 19, Vite 8, Tailwind CSS 3 — site de demonstração, publicado na Vercel ([`docs/deploy.md`](docs/deploy.md)) |
| Notebook | [`AEGIS.ipynb`](AEGIS.ipynb) (Google Colab / Jupyter) |

### Arquitetura resumida

```
aegis.py / AEGIS.ipynb ─┐  (atalhos para iniciantes)
CLI (cli.py) ───────────┼→ varredura.executar()
API (api.py) ───────────┘        │
                                 ├→ analisador.py       parse AST resiliente
                                 ├→ motor/taint.py      fontes → sinks, com sanitização
                                 │   └ motor/catalogo.py  (fontes/sinks/sanitizadores: dado, não lógica)
                                 ├→ poliglota/          JS/TS, Java, PHP, HTML via tree-sitter
                                 ├→ detectores/         detectores Python → Achado (CWE + OWASP)
                                 ├→ configuracao.py     credenciais em .env/YAML/JSON/...
                                 └→ relatorio.py        texto / JSON
```

Sem banco de dados, sem serviços externos, sem persistência. Detalhes: [`docs/arquitetura.md`](docs/arquitetura.md) e [`docs/fluxos.md`](docs/fluxos.md).

### Estrutura do projeto

```
├── aegis.py               # atalho: prepara o ambiente e roda o AEGIS com um comando
├── AEGIS.ipynb            # notebook para Google Colab / Jupyter
├── TOOL/                  # motor SAST "owaspscan" (produto principal)
│   ├── owaspscan/         #   núcleo: achado, analisador, motor/, detectores/, poliglota/,
│   │                      #   varredura, relatorio, cli, api, metricas, configuracao
│   └── tests/             #   pytest + amostras/ (corpus rotulado)
├── frontend/              # site de demonstração (React), publicado na Vercel
├── docs/                  # documentação técnica detalhada
├── sprints/ entregas/     # gestão da disciplina
└── .github/               # templates de issue/PR
```

Inventário arquivo a arquivo: [`docs/estrutura.md`](docs/estrutura.md).

### Documentação

| Documento | Conteúdo |
| --- | --- |
| [`docs/arquitetura.md`](docs/arquitetura.md) | componentes, responsabilidades, decisões técnicas, riscos |
| [`docs/estrutura.md`](docs/estrutura.md) | inventário de arquivos e grafo de dependências |
| [`docs/instalacao.md`](docs/instalacao.md) | setup do zero, verificação, problemas comuns |
| [`docs/configuracao.md`](docs/configuracao.md) | configurações e variáveis de ambiente |
| [`docs/API.md`](docs/API.md) | contrato completo da API HTTP |
| [`docs/banco-de-dados.md`](docs/banco-de-dados.md) | ausência de persistência e entidades em memória |
| [`docs/fluxos.md`](docs/fluxos.md) | fluxos de negócio passo a passo |
| [`docs/seguranca.md`](docs/seguranca.md) | mecanismos de segurança do sistema |
| [`docs/guia-desenvolvedor.md`](docs/guia-desenvolvedor.md) | onboarding: onde investigar bugs, onde implementar |
| [`TOOL/README.md`](TOOL/README.md) | documentação técnica do motor (cobertura, limitações, avaliação) |
| [`TOOL/CLAUDE.md`](TOOL/CLAUDE.md) | princípios de desenvolvimento do motor |

### Para quem vai contribuir

- **Princípios inegociáveis do motor** (`TOOL/CLAUDE.md`): detecção via AST (nunca regex sobre código); classificação sempre derivada do mapa CWE→OWASP em `achado.py`; IDOR e demais heurísticas reportam **candidatos** com confiança baixa; honestidade científica acima de cobertura.
- **Processo**: fases pequenas, teste ao fim de cada fase, um commit por fase que passa nos testes. Veja [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **Comece por**: `TOOL/owaspscan/achado.py` (contrato) → `varredura.py` (pipeline) → `detectores/sqli.py` (menor detector completo). Roteiro completo no [guia do desenvolvedor](docs/guia-desenvolvedor.md).
- **Segurança do repositório**: não commite credenciais reais ([`SECURITY.md`](SECURITY.md)); os segredos em `TOOL/tests/amostras/` são fictícios.
- Encontrou um falso positivo ou uma falha que o AEGIS deixou passar? Abra uma issue com o trecho de código — isso alimenta o corpus de avaliação.

## Licença

Veja [`LICENSE`](LICENSE).
