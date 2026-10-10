# Mapa do projeto

Mapa rápido de localização para desenvolvedores: onde está cada parte do sistema, com caminhos reais. Detalhes de cada item estão nos documentos linkados. Nomes de arquivos seguem o padrão da pasta `docs/` (minúsculo — ver `docs/documentation-audit.md` B5).

```
PROJETO
├── Finalidade .............. SAST para código Python (Django/Flask): detecta 16 CWEs do
│                             OWASP Top 10:2021 via AST + taint tracking, sem executar o
│                             código analisado. Barreira entre código gerado por IA e produção.
│                             → README.md · TOOL/README.md · docs/arquitetura.md
│
├── Arquitetura ............. Núcleo Python em camadas (contrato → AST → motor → detectores
│                             → orquestração → saída → entradas) + API HTTP opcional +
│                             frontend React (protótipo, não integrado).
│                             → docs/arquitetura.md (componentes e decisões)
│                             → docs/fluxos.md (5 fluxos passo a passo)
│                             → docs/estrutura.md (inventário arquivo a arquivo)
│
├── Tecnologias ............. Python ≥3.11 (núcleo 100% stdlib) · FastAPI/Uvicorn (extra
│                             [api]) · pytest (extra [dev]) · React 19 · Vite 8 · Tailwind 3
│                             → TOOL/pyproject.toml · frontend/package.json
│
└── Execução ................ CLI:   cd TOOL && .venv/bin/python -m owaspscan caminho/
                              API:   cd TOOL && .venv/bin/python -m owaspscan.api   (:8000)
                              Site:  cd frontend && npm run dev
                              Métricas: .venv/bin/python -m owaspscan.metricas tests/amostras
                              → docs/instalacao.md (setup completo + verificação)
```

## FRONTEND

```
FRONTEND (protótipo visual — nenhuma chamada de rede ainda)
├── Localização ............. frontend/
├── Componentes principais
│   ├── frontend/index.html ............... shell HTML (favicon, #root, theme-color)
│   ├── frontend/src/main.jsx ............. bootstrap React
│   ├── frontend/src/App.jsx .............. UI inteira: navegação, tema, i18n, abas,
│   │                                       drag&drop, páginas estáticas (382 linhas)
│   ├── frontend/src/translate.js ......... dicionário pt/en
│   ├── frontend/src/index.css ............ diretivas Tailwind
│   └── build/lint: frontend/vite.config.js · tailwind.config.js · postcss.config.js
│       · .oxlintrc.json · package.json (scripts dev/build/lint/preview)
└── Fluxo ................... usuário → index.html → main.jsx → App.jsx
                              (estado local: tema em localStorage['aegis-tema'], idioma,
                              aba ativa, arquivos em useState — nada é enviado)
                              Integração futura prevista: fetch POST /analisar
                              → TOOL/README.md §"API HTTP (para o site)" · docs/fluxos.md §Fluxo 5
```

## BACKEND

```
BACKEND (motor SAST "owaspscan" — sem MVC clássico; mapeamento abaixo)
├── Localização ............. TOOL/owaspscan/
├── "Controllers" (entradas)
│   ├── TOOL/owaspscan/cli.py ............. CLI + exit codes 0/1/2
│   ├── TOOL/owaspscan/__main__.py ........ python -m owaspscan
│   └── TOOL/owaspscan/api.py ............. API HTTP FastAPI (extra [api])
├── "Services" (processamento)
│   ├── TOOL/owaspscan/varredura.py ....... orquestração: executar() — o pipeline inteiro
│   ├── TOOL/owaspscan/analisador.py ...... descoberta/parse AST resiliente
│   ├── TOOL/owaspscan/motor/taint.py ..... rastreamento fonte→sink (ponto fixo)
│   ├── TOOL/owaspscan/motor/catalogo.py .. fontes/sinks/sanitizadores (dado declarativo)
│   ├── TOOL/owaspscan/motor/estrutura.py . consultas estruturais da AST
│   ├── TOOL/owaspscan/motor/credenciais.py regras CWE-798 + mascaramento de segredos
│   ├── TOOL/owaspscan/motor/confianca.py . calibração alta/média/baixa
│   ├── TOOL/owaspscan/configuracao.py .... parsers .env/YAML/JSON/INI/TOML/.properties
│   └── TOOL/owaspscan/relatorio.py ....... formatação texto/JSON (módulo puro)
├── Regras de negócio (detecção)
│   └── TOOL/owaspscan/detectores/ ........ 10 detectores (16 CWEs) + base.py (Protocol)
│       sqli · xss · idor · xxe · path_traversal · open_redirect · csrf ·
│       autorizacao · autenticacao (6) · credenciais (2) · comum.py (helpers)
├── Contrato central ........ TOOL/owaspscan/achado.py (Achado + MAPA_CWE_OWASP fechado)
│   API pública do pacote ... TOOL/owaspscan/__init__.py (from owaspscan import executar)
└── "Repositories" .......... NÃO EXISTEM — não há camada de acesso a dados
                              → docs/arquitetura.md · docs/estrutura.md · docs/guia-desenvolvedor.md
```

## BANCO

```
BANCO
├── Tecnologia .............. NENHUMA — o projeto não tem banco de dados nem persistência
├── Modelos ................. não se aplica; entidades são dataclasses em memória:
│                             Achado (achado.py) · Varredura (varredura.py) ·
│                             FalhaDeLeitura (analisador.py) · Escopo/Procedencia (motor/taint.py)
├── Relacionamentos ......... não se aplica
└── Armazenamento real ...... efêmero: TemporaryDirectory por requisição da API
                              (TOOL/owaspscan/api.py:123-130) + localStorage do tema
                              (frontend/src/App.jsx:33,61)
                              → docs/banco-de-dados.md
```

## API

```
API (TOOL/owaspscan/api.py — única API do projeto)
├── Endpoints principais
│   ├── POST /analisar .................... análise de código (JSON ou multipart/form-data;
│   │                                       ≤50 arquivos, ≤1 MB cada; resposta = para_dict())
│   ├── GET  /saude ....................... {"status":"ok","versao":"0.2.0"}
│   └── GET  /docs · /redoc · /openapi.json  documentação OpenAPI (automática do FastAPI)
├── Autenticação .......................... NENHUMA (API aberta; único controle = CORS)
├── CORS .................................. CORSMiddleware (api.py:67-72), origens via
│                                           OWASPSCAN_ORIGENS (padrão *)
├── Erros ................................. 400 · 413 · 415 · 422 ({"detail": "..."});
│                                           sintaxe inválida = 200 + varredura.falhas[]
└── Testes ................................ TOOL/tests/test_api.py (26 funções)
                                            → docs/api.md (contrato completo)
```

## CONFIGURAÇÃO

```
CONFIGURAÇÃO
├── Variáveis de ambiente ... OWASPSCAN_HOST · OWASPSCAN_PORTA · OWASPSCAN_ORIGENS
│                             (todas opcionais, só da API — TOOL/owaspscan/api.py:46,223-224;
│                             não existe .env no projeto)
├── Limites hardcoded ....... TOOL/owaspscan/api.py:40-43 (50 arquivos, 1 MB, nomes)
├── Pacote/pytest ........... TOOL/pyproject.toml (extras [api]/[dev])
├── Frontend ................ frontend/vite.config.js · tailwind.config.js (darkMode:'class')
│                             · postcss.config.js · .oxlintrc.json · package.json
├── Qualidade ............... .editorconfig · .markdownlint.json · .gitignore (raiz/TOOL/frontend)
└── GitHub .................. .github/ISSUE_TEMPLATE/*.yml · .github/PULL_REQUEST_TEMPLATE.md
                                            → docs/configuracao.md
```

## TESTES

```
TESTES
├── Localização ............. TOOL/tests/ (19 arquivos, 356 funções de teste; coleta pytest
│                             é maior — testes parametrizados). Frontend: SEM testes.
├── Execução ................ cd TOOL && .venv/bin/python -m pytest -v
├── Apoio ................... TOOL/tests/conftest.py (rodar_detector, linhas_esperadas)
├── Corpus/gabarito ......... TOOL/tests/amostras/ — vulneravel/ (11 .py + config/) ·
│                             seguro/ (13 .py + config/) · analisador/ (2 .py);
│                             gabarito em comentários (# achado: / # limitacao:)
└── Avaliação do motor ...... TOOL/owaspscan/metricas.py + amostras
                              (python -m owaspscan.metricas tests/amostras)
                                            → docs/guia-desenvolvedor.md §10/§16
```

## INFRAESTRUTURA

```
INFRAESTRUTURA
├── Docker .................. NÃO EXISTE (os docker-compose.yml em TOOL/tests/amostras/
│                             são fixtures de teste do detector de credenciais)
├── CI/CD ................... NÃO EXISTE (.github/workflows/ ausente; gate possível hoje =
│                             exit code da CLI, TOOL/owaspscan/cli.py:24-26)
├── Deploy .................. nenhum — execução 100% local (venv + npm)
└── Logs/monitoramento ...... nenhum próprio; stdout/stderr + logs padrão do Uvicorn;
                              healthcheck = GET /saude
                                            → docs/seguranca.md · docs/instalacao.md
```

## DOCUMENTAÇÃO

```
DOCUMENTAÇÃO
├── README.md ..................... porta de entrada do projeto
├── TOOL/README.md ................ doc técnica do motor (cobertura, limitações, avaliação)
├── TOOL/CLAUDE.md ................ princípios de desenvolvimento (obrigatório ler)
├── docs/arquitetura.md ........... componentes, fluxos, decisões, riscos
├── docs/estrutura.md ............. inventário de arquivos + grafo de dependências
├── docs/instalacao.md ............ setup do zero, verificação, problemas comuns
├── docs/configuracao.md .......... todas as configurações e env vars
├── docs/api.md ................... contrato completo da API HTTP
├── docs/banco-de-dados.md ........ ausência de persistência + entidades em memória
├── docs/fluxos.md ................ fluxos de negócio passo a passo
├── docs/seguranca.md ............. mecanismos de segurança (implementado/parcial/ausente)
├── docs/guia-desenvolvedor.md .... onboarding: bugs, novas features, testes
├── docs/documentation-audit.md ... auditoria doc × código + nota pós-correção
├── docs/MAPA-DO-PROJETO.md ....... este documento
├── SECURITY.md ................... política de segredos/incidentes
├── CHANGELOG.md .................. histórico de mudanças
└── Pendências .................... docs/requisitos.md (template) · docs/decisoes/ (sem ADRs)
                                    · docs/reunioes/ (template) · sprints/ · entregas/
```

## Atalhos de navegação

| Quero... | Ir para |
| --- | --- |
| Entender o produto em 30 min | `TOOL/CLAUDE.md` → `TOOL/README.md` → `docs/arquitetura.md` |
| Instalar e rodar | `docs/instalacao.md` |
| Investigar um bug | `docs/guia-desenvolvedor.md` §11 (tabela por sintoma) |
| Criar um detector novo | `docs/guia-desenvolvedor.md` §12 → `TOOL/owaspscan/detectores/sqli.py` (modelo) |
| Mexer na API | `docs/api.md` → `TOOL/owaspscan/api.py` + `TOOL/tests/test_api.py` |
| Mexer no site | `frontend/src/App.jsx` + `frontend/src/translate.js` (2 idiomas!) |
| Entender uma CWE específica | `TOOL/README.md` §Cobertura → `TOOL/owaspscan/detectores/<tema>.py` → `TOOL/tests/amostras/` |
| Ver o contrato dos dados | `TOOL/owaspscan/achado.py` (Achado) → `relatorio.py` (`para_dict`) |
