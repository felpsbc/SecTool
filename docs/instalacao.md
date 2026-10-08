# Instalação

Guia para configurar o projeto AEGIS do zero. Todas as versões, comandos e dependências abaixo foram confirmados diretamente nos arquivos do repositório (`TOOL/pyproject.toml`, `TOOL/README.md`, `frontend/package.json`, `frontend/package-lock.json`, `owaspscan/api.py`, `owaspscan/cli.py`). Nada aqui é estimado.

O projeto tem **duas partes independentes** — instale só o que for usar:

| Parte | O que é | Stack |
| --- | --- | --- |
| **A. TOOL** | Motor SAST + CLI (núcleo) e API HTTP (opcional) | Python ≥3.11, stdlib no núcleo |
| **C. Frontend** | Interface web (protótipo; ainda não consome a API) | Node.js + npm |

Não há banco de dados, serviço externo, Docker ou CI — nada além do que está documentado aqui precisa ser instalado.

## 1. Sistema operacional

Nenhum arquivo do projeto especifica SO suportado. **[NECESSÁRIO CONFIRMAR]** com a equipe.

Evidências no código:

- Os comandos oficiais do `TOOL/README.md` usam padrão POSIX (`.venv/bin/python`), típicos de Linux/macOS.
- O código é multiplataforma: `api.py` trata explicitamente caminhos Windows (`PureWindowsPath`, `api.py:28`), e o núcleo usa `pathlib`.

Este guia mostra comandos para Linux/macOS, com a variante Windows quando difere.

## 2. Linguagens e versões necessárias

| Linguagem | Versão | Onde foi confirmado |
| --- | --- | --- |
| Python | **≥ 3.11** | `TOOL/pyproject.toml` (`requires-python = ">=3.11"`); o código usa `match/case` e tipagem `X \| None` |
| Node.js | **^20.19.0 ou ≥22.12.0** | campo `engines` do vite 8.3.1 no `frontend/package-lock.json` (o `package.json` não declara `engines` nem existe `.nvmrc`) |
| npm | **[NECESSÁRIO CONFIRMAR]** — nenhuma versão mínima declarada; usar o npm que acompanha o Node | `frontend/package-lock.json` (lockfile v3) |

Verifique antes de começar:

```bash
python3 --version   # deve ser >= 3.11
node --version      # deve ser 20.19+ ou 22.12+
npm --version
```

## 3. Gerenciadores de pacotes

| Ferramenta | Uso | Origem |
| --- | --- | --- |
| `venv` + `pip` | ambiente virtual e pacotes Python | comandos oficiais em `TOOL/README.md` §Ambiente |
| `npm` | pacotes do frontend | `package-lock.json` presente em `frontend/` |
| `setuptools ≥ 68` | apenas no build do pacote `owaspscan` (instalado automaticamente pelo pip) | `TOOL/pyproject.toml` `[build-system]` |

Não há poetry, pipenv, uv, yarn ou pnpm configurados no projeto.

## 4. Dependências

### TOOL (`TOOL/pyproject.toml`)

| Grupo | Pacotes | Quando instalar |
| --- | --- | --- |
| **Núcleo** | **nenhum** (`dependencies = []`) — só stdlib | sempre |
| extra `dev` | pytest ≥8.0, httpx ≥0.27 | para rodar os testes |
| extra `api` | fastapi ≥0.110, uvicorn ≥0.29, python-multipart ≥0.0.9 | para subir a API HTTP |

Os extras são isolados de propósito: o scanner funciona 100% offline sem nenhum pacote de terceiros.

### Frontend (`frontend/package.json`)

| Grupo | Pacotes |
| --- | --- |
| dependências | react ^19.2.8, react-dom ^19.2.8 |
| devDependencies | vite ^8.3.0, @vitejs/plugin-react ^6.1.1, tailwindcss ^3.4.19, postcss ^8.5.28, autoprefixer ^10.6.1, oxlint ^1.81.0, @types/react ^19.2.18, @types/react-dom ^19.2.7 |

## 5. Banco de dados

**Nenhum.** O projeto não usa banco de dados nem persistência de qualquer tipo. A API grava os uploads numa pasta temporária (`tempfile.TemporaryDirectory`, `api.py:125`) que é destruída ao final de cada requisição.

## 6. Serviços externos

**Nenhum.** Nenhuma parte do código faz chamadas a serviços de terceiros. A API apenas recebe requisições HTTP localmente.

## 7. Variáveis de ambiente

Todas **opcionais** e usadas somente pela API HTTP (`api.py:46,223-224`). Não existe arquivo `.env` no projeto, e o frontend não usa nenhuma variável `VITE_*`.

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `OWASPSCAN_HOST` | `127.0.0.1` | host em que o Uvicorn escuta |
| `OWASPSCAN_PORTA` | `8000` | porta do servidor |
| `OWASPSCAN_ORIGENS` | `*` | origens permitidas no CORS, separadas por vírgula |

Exemplo:

```bash
OWASPSCAN_PORTA=9000 .venv/bin/python -m owaspscan.api
```

## 8. Configurações necessárias

Nenhuma configuração adicional é obrigatória:

- O pytest já está configurado no `TOOL/pyproject.toml` (`testpaths = ["tests"]`).
- Vite, Tailwind, PostCSS e Oxlint já vêm configurados em `frontend/` (`vite.config.js`, `tailwind.config.js`, `postcss.config.js`, `.oxlintrc.json`).
- Não há proxy configurado no `vite.config.js` para a API (o frontend ainda não a consome — ver [Problemas comuns](#12-problemas-comuns-de-instalação)).

## 9. Comandos de instalação

### Parte A — TOOL (motor + CLI)

```bash
cd TOOL
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"      # núcleo + testes
```

Windows:

```bat
cd TOOL
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

Para habilitar também a API HTTP (Parte B):

```bash
.venv/bin/python -m pip install -e ".[api]"
# ou ambos de uma vez:
.venv/bin/python -m pip install -e ".[dev,api]"
```

### Parte C — Frontend

```bash
cd frontend
npm install        # usa o package-lock.json (versões congeladas)
```

## 10. Comandos para iniciar o projeto

### CLI (análise estática)

```bash
cd TOOL
.venv/bin/python -m owaspscan caminho/do/projeto      # analisa um diretório
.venv/bin/python -m owaspscan app.py                  # analisa um arquivo
.venv/bin/python -m owaspscan app.py --json | jq '.resumo'   # saída JSON
.venv/bin/python -m owaspscan .env                    # arquivo de configuração isolado
.venv/bin/python -m owaspscan --versao
```

Códigos de saída (`cli.py:5-11`): `0` sem achado de severidade alta · `1` com achado alto · `2` erro de uso (caminho inexistente). Candidatos heurísticos não alteram o código de saída.

### API HTTP

```bash
cd TOOL
.venv/bin/python -m owaspscan.api
# servidor em http://127.0.0.1:8000 — documentação interativa em /docs
```

### Frontend

```bash
cd frontend
npm run dev        # servidor de desenvolvimento (URL exibida no terminal, padrão http://localhost:5173)
npm run build      # build de produção em dist/
npm run preview    # serve o build localmente
npm run lint       # oxlint
```

### Avaliação (métricas do motor)

```bash
cd TOOL
.venv/bin/python -m owaspscan.metricas tests/amostras
```

## 11. Como verificar se o projeto está funcionando

Execute em ordem; cada passo tem resultado esperado determinado pelos arquivos do projeto.

**1. Testes do TOOL** (~336 testes):

```bash
cd TOOL && .venv/bin/python -m pytest -v
```

Esperado: todos passam, sem erros de coleta.

**2. CLI detecta vulnerabilidades** (corpus de teste do próprio projeto):

```bash
.venv/bin/python -m owaspscan tests/amostras/vulneravel ; echo "exit=$?"
.venv/bin/python -m owaspscan tests/amostras/seguro ; echo "exit=$?"
```

Esperado: a primeira imprime relatório com achados (SQL Injection, XSS, credenciais etc.) e `exit=1`; a segunda tem seção de achados vazia/sem severidade alta e `exit=0`.

**3. Métricas batem com o declarado** (`TOOL/README.md` §Avaliação):

```bash
.venv/bin/python -m owaspscan.metricas tests/amostras
```

Esperado: tabela por CWE com precisão 1.00, recall 0.98, F1 0.99 no geral.

**4. API no ar** (se instalou o extra `[api]`):

```bash
.venv/bin/python -m owaspscan.api &          # ou em outro terminal
curl http://127.0.0.1:8000/saude
```

Esperado: `{"status":"ok","versao":"0.2.0"}`. Teste de análise (exemplo do `TOOL/README.md`):

```bash
curl -X POST http://127.0.0.1:8000/analisar \
  -H "Content-Type: application/json" \
  -d '{"codigo": "from flask import request\nimport sqlite3\ndef view():\n    cursor.execute(\"SELECT * FROM t WHERE id=\" + request.args[\"id\"])\n", "nome": "app.py"}'
```

Esperado: JSON com `resumo` e `achados` contendo CWE-89.

**5. Frontend** :

```bash
cd frontend && npm run dev
```

Esperado: página do AEGIS abre no navegador (logo "A", abas FICHEIRO/URL/CÓDIGO, alternância de tema e idioma funcionam). `npm run lint` não deve apontar erros.

## 12. Problemas comuns de instalação

| Sintoma | Causa provável | Solução |
| --- | --- | --- |
| `SyntaxError` ao instalar/rodar o TOOL | Python < 3.11 (o código usa `match/case`) | `python3 --version`; use um interpretador ≥3.11 para criar o venv |
| `ModuleNotFoundError: No module named 'fastapi'` (ou uvicorn/pydantic) ao rodar `python -m owaspscan.api` | API instalada sem o extra | `.venv/bin/python -m pip install -e ".[api]"` — o núcleo de propósito não inclui FastAPI |
| `ModuleNotFoundError: pytest` / `httpx` | instalado sem o extra `dev` | `.venv/bin/python -m pip install -e ".[dev]"` |
| `'python' não é reconhecido` / caminhos `.venv/bin/...` não existem | comandos POSIX no Windows | usar `.venv\Scripts\python` (ou ativar o venv com `.venv\Scripts\activate`) |
| `npm install` falha com erro de `engines` | Node fora da faixa `^20.19.0 \|\| >=22.12.0` exigida pelo Vite 8 | instalar/atualizar o Node para 20.19+ ou 22.12+ |
| Porta 8000 ocupada ao subir a API | outro processo usando a porta | `OWASPSCAN_PORTA=9000 .venv/bin/python -m owaspscan.api` |
| Frontend "não analisa nada" ao enviar arquivo/código | **não é falha de instalação**: o frontend é um protótipo e ainda não chama a API (nenhum `fetch` em `frontend/src/`); também não há proxy no `vite.config.js` | para analisar, usar a CLI ou chamar `POST /analisar` diretamente (curl/`/docs`) |
| Navegador bloqueia chamada à API (CORS) | `OWASPSCAN_ORIGENS` restrito sem incluir a origem do site | incluir a origem (ex.: `OWASPSCAN_ORIGENS=http://localhost:5173`) ou manter o padrão `*` em desenvolvimento |
| Erro de build do pacote (`setuptools`) | setuptools antigo no ambiente de build | o pip baixa `setuptools>=68` automaticamente; se falhar, `pip install -U pip setuptools` |
| `erro: caminho nao encontrado` e exit code 2 na CLI | caminho inexistente passado como argumento | verificar o caminho; a CLI exige arquivo `.py`, arquivo de configuração ou diretório existente |

## Observações finais

- **Sem infraestrutura adicional**: não existem Dockerfile, docker-compose de deploy, Makefile, scripts de setup automático ou workflows de CI no repositório (os `docker-compose.yml` em `TOOL/tests/amostras/` são apenas amostras de código vulnerável usadas nos testes).
- **Instalação mínima possível**: apenas a Parte A sem extras já permite usar a CLI — o núcleo não tem nenhuma dependência de terceiros.
- Detalhes de arquitetura e do contrato da API: `docs/arquitetura.md` e `TOOL/README.md`.
