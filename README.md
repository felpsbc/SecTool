# AEGIS-CODE

Ferramenta de análise estática de segurança (SAST) que atua como barreira entre código gerado por IA e o ambiente de produção: detecta vulnerabilidades do OWASP Top 10:2021 em código Python (Django/Flask) e em arquivos de configuração, **sem executar o código analisado** — apenas AST e taint tracking.

## Identificação do repositório

| Campo | Informação |
| --- | --- |
| Instituição | CEUB |
| Organização no GitHub | CampusCEUB |
| Professor(a) responsável pela criação: | Professor Lucas Rodrigues - 128050 |
| Equipe | Felipe Barcelos de Carvalho, Lucas de Salles Almeida Moura, João Marcelo Guimarães Dourado, Marcos Vinícius Rocha |
| IDProjeto | 20260229 |

## Problema e objetivo

Estudos indicam que 40–45% do código gerado por IA contém vulnerabilidades conhecidas (Pearce, 2022; Veracode, 2025), e esse código costuma ir para produção sem revisão (Perry, 2023). O objetivo do AEGIS é detectar essas falhas antes do deploy, com priorização por severidade/confiança e remediação educativa (cada achado traz explicação e recomendação de correção).

## Principais funcionalidades

- **16 CWEs mapeadas ao OWASP Top 10:2021**: SQL Injection, XSS, IDOR (candidatos), Path Traversal, Open Redirect, CSRF, rota sem autorização, XXE, JWT sem verificação, hash fraco, senha em texto puro, cookies inseguros, sessão longa, login sem rate limit e credenciais fixas (código **e** configuração: `.env`, YAML, JSON, INI, TOML, `.properties`). Cobertura e técnicas: [`TOOL/README.md`](TOOL/README.md#cobertura).
- **CLI com exit codes para CI/CD**: `0` sem achado alto, `1` com achado alto, `2` erro de uso — candidatos heurísticos não quebram builds.
- **API HTTP** (`POST /analisar`) para integração com o site, aceitando JSON ou upload multipart; Swagger em `/docs`.
- **Relatório texto e JSON** com resumo executivo, severidade, confiança calibrada e recomendações.
- **Autoavaliação mensurável**: corpus rotulado com gabarito embutido; precisão/recall/F1 por CWE (`python -m owaspscan.metricas`).
- **Privacidade por design**: nenhum banco de dados; uploads da API são destruídos por requisição; segredos detectados chegam mascarados no relatório.

## Tecnologias

| Parte | Stack |
| --- | --- |
| Motor (`TOOL/`) | Python ≥3.11, **somente stdlib** no núcleo (`ast`, `dataclasses`, `pathlib`) |
| API HTTP | FastAPI + Uvicorn (extra opcional `[api]` — o scanner funciona sem elas) |
| Testes | pytest (+ httpx para a API) |
| Frontend (`frontend/`) | React 19, Vite 8, Tailwind CSS 3 — **protótipo de interface, ainda não integrado à API** |

## Arquitetura resumida

```
CLI (cli.py) ──┐
               ├→ varredura.executar()
API (api.py) ──┘        │
                        ├→ analisador.py       parse AST resiliente
                        ├→ motor/taint.py      fontes → sinks, com sanitização
                        │   └ motor/catalogo.py  (fontes/sinks/sanitizadores: dado, não lógica)
                        ├→ detectores/         11 módulos, 16 CWEs → Achado
                        ├→ configuracao.py     credenciais em .env/YAML/JSON/...
                        └→ relatorio.py        texto / JSON
```

Sem banco de dados, sem serviços externos, sem persistência. Detalhes: [`docs/arquitetura.md`](docs/arquitetura.md) e [`docs/fluxos.md`](docs/fluxos.md).

## Requisitos

- **Python ≥ 3.11** (`TOOL/pyproject.toml`)
- **Node.js ^20.19.0 ou ≥22.12.0** + npm (somente para o frontend; exigência do Vite 8)
- Nenhum banco de dados ou serviço externo é necessário.

## Instalação e execução

```bash
# Motor + CLI (núcleo, sem dependências de terceiros)
cd TOOL
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"        # adicione "api" se for subir o servidor

# Analisar um projeto/arquivo
.venv/bin/python -m owaspscan caminho/do/projeto
.venv/bin/python -m owaspscan app.py --json | jq '.resumo'

# API HTTP → http://127.0.0.1:8000/docs
.venv/bin/python -m pip install -e ".[api]"
.venv/bin/python -m owaspscan.api

# Frontend → http://localhost:5173
cd frontend && npm install && npm run dev
```

Windows: use `.venv\Scripts\python`. Passo a passo completo, verificação e problemas comuns: [`docs/instalacao.md`](docs/instalacao.md).

## Configuração

Nenhuma configuração é obrigatória. A API aceita 3 variáveis de ambiente opcionais: `OWASPSCAN_HOST` (padrão `127.0.0.1`), `OWASPSCAN_PORTA` (`8000`) e `OWASPSCAN_ORIGENS` (CORS, padrão `*`). Detalhes e impacto: [`docs/configuracao.md`](docs/configuracao.md).

## Testes

```bash
cd TOOL
.venv/bin/python -m pytest -v                        # ~336 testes
.venv/bin/python -m owaspscan.metricas tests/amostras  # precisão/recall/F1 do motor
```

O corpus de avaliação fica em `TOOL/tests/amostras/`, com gabarito embutido em comentários (`# achado:` / `# limitacao:`). O frontend não possui testes.

## Estrutura do projeto

```
├── TOOL/                  # motor SAST "owaspscan" (produto principal)
│   ├── owaspscan/         #   núcleo: achado, analisador, motor/, detectores/,
│   │                      #   varredura, relatorio, cli, api, metricas, configuracao
│   └── tests/             #   pytest + amostras/ (corpus rotulado)
├── frontend/              # SPA React (protótipo visual, sem integração com a API)
├── docs/                  # documentação técnica detalhada (ver abaixo)
├── sprints/ entregas/     # gestão da disciplina (templates)
└── .github/               # templates de issue/PR (sem CI configurado)
```

Inventário arquivo a arquivo: [`docs/estrutura.md`](docs/estrutura.md).

## Documentação

| Documento | Conteúdo |
| --- | --- |
| [`docs/arquitetura.md`](docs/arquitetura.md) | componentes, responsabilidades, decisões técnicas, riscos |
| [`docs/estrutura.md`](docs/estrutura.md) | inventário de arquivos e grafo de dependências |
| [`docs/instalacao.md`](docs/instalacao.md) | setup do zero, verificação, problemas comuns |
| [`docs/configuracao.md`](docs/configuracao.md) | todas as configurações e variáveis de ambiente |
| [`docs/API.md`](docs/API.md) | contrato completo da API HTTP |
| [`docs/banco-de-dados.md`](docs/banco-de-dados.md) | ausência de persistência e entidades em memória |
| [`docs/fluxos.md`](docs/fluxos.md) | fluxos de negócio passo a passo |
| [`docs/SEGURANCA.md`](docs/SEGURANCA.md) | mecanismos de segurança do sistema |
| [`docs/guia-desenvolvedor.md`](docs/guia-desenvolvedor.md) | onboarding: onde investigar bugs, onde implementar |
| [`TOOL/README.md`](TOOL/README.md) | documentação técnica do motor (cobertura, limitações, avaliação) |
| [`TOOL/CLAUDE.md`](TOOL/CLAUDE.md) | princípios de desenvolvimento do motor |

## Informações importantes para desenvolvedores

- **Princípios inegociáveis do motor** (`TOOL/CLAUDE.md`): detecção via AST (nunca regex sobre código); classificação sempre derivada do mapa CWE→OWASP em `achado.py`; IDOR e demais heurísticas reportam **candidatos** com confiança baixa; honestidade científica acima de cobertura.
- **Processo**: fases pequenas, teste ao fim de cada fase, um commit por fase que passa nos testes.
- **Comece por**: `TOOL/owaspscan/achado.py` (contrato) → `varredura.py` (pipeline) → `detectores/sqli.py` (menor detector completo). Roteiro completo no [guia do desenvolvedor](docs/guia-desenvolvedor.md).
- **Estado atual**: motor maduro (19 fases, métricas: precisão 1.00 / recall 0.98 / F1 0.99 em corpus próprio — consistência interna, não generalização); frontend é protótipo e ainda não consome a API; não há CI/CD, Docker nem hook de pre-commit implementados (o bloqueio de merges citado na solução proposta é realizado hoje via exit code da CLI).
- **Segurança do repositório**: não commite credenciais reais (`SECURITY.md`); os segredos em `TOOL/tests/amostras/` são fictícios, usados como corpus de teste.
