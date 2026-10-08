# Arquitetura

Documento de arquitetura real do projeto AEGIS, baseado exclusivamente no código e nos arquivos existentes no repositório (commit `a90120a`). Substitui o template genérico anterior.

## Contexto técnico

O AEGIS é uma ferramenta de análise estática de segurança (SAST) para código Python (Django/Flask), focada no OWASP Top 10:2021. O repositório contém três partes:

| Parte | Localização | Stack | Estado |
| --- | --- | --- | --- |
| Motor SAST (núcleo + CLI + API) | `TOOL/owaspscan/` | Python 3.11+, stdlib apenas no núcleo; FastAPI opcional | Maduro, 19 fases, ~336 testes |
| Frontend web | `frontend/` | React 19, Vite 8, Tailwind CSS 3 | Protótipo visual, **não integrado à API** |
| Gestão acadêmica | `docs/`, `sprints/`, `entregas/`, `.github/` | Markdown | Maioria em estado de template |

Restrições técnicas declaradas do motor (ver `TOOL/README.md` e `TOOL/CLAUDE.md`):

- Detecção baseada em AST (módulo `ast` da stdlib), **nunca regex** sobre código-fonte. A única exceção declarada são arquivos de configuração não-Python (`.env`, YAML, JSON, INI, TOML, `.properties`), lidos por parsers de linha/gramática própria em `configuracao.py`.
- Motor de taint **intraprocedural** (não atravessa chamadas entre funções do projeto) e **insensível a fluxo** (nome contaminado em qualquer ponto do escopo conta como contaminado no escopo inteiro).
- Chamadas desconhecidas propagam taint (pessimista: prefere falso positivo a falso negativo silencioso).
- Cego a arquivos de template (`.html`/Jinja2 não são analisados).
- O código analisado **nunca é executado**, apenas parseado.

## Visão geral

```
  Desenvolvedor/CI                     Usuário web
       │                                    │
       ▼                                    ▼
 ┌──────────────┐                   ┌──────────────────┐
 │  CLI         │                   │  Frontend React  │  (protótipo visual —
 │  cli.py      │                   │  frontend/       │   não chama a API)
 └──────┬───────┘                   └──────────────────┘
        │        ┌─────────────────────┐
        │        │  API HTTP (FastAPI) │  opcional (extra [api])
        │        │  api.py             │  POST /analisar · GET /saude
        │        └──────────┬──────────┘
        ▼                   ▼
 ┌────────────────────────────────────────┐
 │  ORQUESTRAÇÃO — varredura.executar()   │
 ├────────────────────────────────────────┤
 │  analisador (AST)  →  motor/taint      │
 │        ↓                    ↓          │
 │  detectores (16 CWEs) ← motor/catalogo │
 │        ↓         motor/estrutura       │
 │  configuracao →  motor/credenciais     │
 │        ↓         motor/confianca       │
 │  achado (contrato) → relatorio (saída) │
 └────────────────────────────────────────┘
        ↑
 metricas.py (autoavaliação contra corpus rotulado em tests/amostras)

 Banco de dados: NENHUM · Serviços externos: NENHUM · Infra: NENHUMA
```

Camadas do núcleo, da base para o topo:

1. **Contrato** (`achado.py`) — tipo `Achado` e mapa CWE→OWASP canônico.
2. **AST** (`analisador.py`) — descoberta, parse resiliente, localização de nós.
3. **Motor** (`motor/`) — taint, catálogo declarativo, consultas estruturais, regras de credenciais, calibração de confiança.
4. **Detectores** (`detectores/`) — 11 módulos que interpretam o motor e emitem achados.
5. **Orquestração** (`varredura.py`) — monta o pipeline completo.
6. **Saída** (`relatorio.py`) — formatação pura em texto/JSON.
7. **Entradas** (`cli.py`, `api.py`) — interfaces de usuário.
8. **Avaliação** (`metricas.py`) — precisão/recall contra corpus rotulado.

## Componentes

### CLI

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/cli.py`, `TOOL/owaspscan/__main__.py` |
| Responsabilidade | Interface de linha de comando (`python -m owaspscan caminho [--json] [--versao]`). Invoca a varredura, imprime relatório (texto no stdout; com `--json`, JSON no stdout e resumo no stderr) e devolve código de saída: `0` sem achado de severidade alta, `1` com achado alto, `2` erro de uso |
| Dependências | stdlib (`argparse`, `json`, `sys`, `pathlib`) |
| Utiliza | `varredura.executar`, `varredura.VERSAO`, `relatorio.formatar_texto`, `relatorio.para_dict` |
| Utilizado por | Desenvolvedor no terminal; pensado para CI/pre-commit (integração ainda não implementada) |

Decisão registrada em código: candidatos heurísticos (confiança baixa) **não alteram o código de saída** — "não seria honesto quebrar um build com base em suposição" (`cli.py:10-11`).

### API HTTP

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/api.py` |
| Responsabilidade | Camada web opcional (extra `[api]`): `POST /analisar` aceita `application/json` **ou** `multipart/form-data`; `GET /saude` retorna status/versão; OpenAPI automático em `/docs`. Valida entrada hostil antes de analisar e devolve exatamente o mesmo JSON do `--json` (`para_dict`), com `raiz` substituída por `"envio"` |
| Dependências | fastapi, uvicorn, python-multipart, pydantic, starlette — **fora do núcleo de propósito**; o scanner continua rodando só com stdlib |
| Utiliza | `varredura.executar`/`VERSAO`, `relatorio.para_dict`, `configuracao.formato_de` |
| Utilizado por | Qualquer cliente HTTP. O frontend deveria consumi-la, mas **ainda não consome** (nenhum `fetch` em `frontend/src/`) |
| Configuração | `OWASPSCAN_HOST` (padrão `127.0.0.1`), `OWASPSCAN_PORTA` (padrão `8000`), `OWASPSCAN_ORIGENS` (CORS, padrão `*`) — `api.py:46,223-224` |

Validações de entrada (`montar_envios`, `nome_seguro`):

- Nome de arquivo reduzido ao nome-base (descarta qualquer caminho → sem path traversal);
- Tipos aceitos: `.py` e configuração (`.env`, YAML, JSON, INI, TOML, `.properties`);
- Máximo 50 arquivos por envio, 1 MB por arquivo (leitura com 1 byte extra para detectar excesso sem ler tudo);
- Nomes duplicados rejeitados; envio vazio rejeitado;
- Erros: `400` (vazio/tipo inválido/duplicado), `413` (tamanho/quantidade), `415` (Content-Type), `422` (JSON malformado).

A varredura é CPU-bound e roda via `run_in_threadpool`, fora do event loop (`api.py:199-200`).

### Orquestração (Varredura)

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/varredura.py` |
| Responsabilidade | Pipeline completo: `executar(raiz)` descobre e analisa arquivos Python, roda taint + 15 detectores por arquivo, lê arquivos de configuração e roda o detector de credenciais sobre eles, agregando tudo no dataclass imutável `Varredura` (achados ordenados por arquivo/linha/CWE, contadores de arquivos, falhas de leitura, momento, versão). Propriedades derivadas: `confirmados` (taint), `candidatos` (heurísticos), `tem_severidade_alta` |
| Dependências | stdlib apenas |
| Utiliza | `analisador`, `configuracao`, `motor.catalogo` (`CATALOGO_PADRAO`), `motor.taint`, `detectores.base` (Protocol `Detector` + `ordenar_achados`) e todos os 11 módulos de detectores |
| Utilizado por | `cli.py`, `api.py`, `metricas.py`, testes |

`detectores_padrao()` (`varredura.py:44-62`) fixa a ordem dos 15 detectores no relatório. Separação deliberada: `varredura.py` faz I/O e execução; `relatorio.py` só formata.

### Contrato de Achado

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/achado.py` |
| Responsabilidade | Tipo central do sistema. `Achado` (frozen dataclass) tem 10 campos fixos: `arquivo`, `linha`, `cwe`, `owasp`, `vulnerabilidade`, `severidade`, `confianca`, `trecho`, `descricao`, `recomendacao`. `MAPA_CWE_OWASP` define as 16 CWEs suportadas e sua classificação canônica; `criar_achado()` deriva `owasp` e `vulnerabilidade` do mapa — **nenhum detector pode inventar classificação**. `__post_init__` valida tudo e lança `ClassificacaoInvalida` |
| Dependências | nenhuma (base do sistema) |
| Utilizado por | todos os detectores, `relatorio`, `metricas`, testes (`test_contrato.py` protege o mapa) |

CWEs cobertas: 89, 79, 639, 22, 601, 352, 862, 916, 256, 611, 614, 1004, 287, 307, 613, 798. O mapeamento segue a lista oficial "List of Mapped CWEs" do OWASP Top 10:2021 — a categoria OWASP vem da CWE, não do tema do detector (por isso hash fraco de senha aparece em A02).

### Camada AST (Analisador)

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/analisador.py` |
| Responsabilidade | Descoberta de arquivos `.py` (ordem estável, ignorando `.git`, `.venv`, `node_modules`, `build`, etc.), parse resiliente (`tokenize.open` + `ast.parse`) e localização de nós (`linha_de`, `trecho_de` com normalização e truncamento a 120 chars). Falhas de sintaxe/codificação/IO viram `FalhaDeLeitura` — registradas no relatório, nunca fatais. `analisar_texto()` parseia código em memória (testes e API) |
| Dependências | stdlib (`ast`, `tokenize`, `pathlib`) |
| Utilizado por | `varredura`, `motor.taint`, testes |

Esta camada "não sabe nada sobre vulnerabilidades" — entrega `ArquivoAnalisado` (caminho relativo, fonte, árvore) para as camadas superiores.

### Motor de Taint

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/motor/taint.py` |
| Responsabilidade | Rastrear dados de fontes não confiáveis até valores/expressões. `analisar_taint()` devolve um `Escopo` por módulo/classe/função, com nomes `contaminados` → conjunto de `Procedencia` (fonte, sanitizadores aplicados no caminho, `via_chamada`, `condicional`). Propagação por **ponto fixo** (repete até estabilizar → independente da ordem textual). Semeia automaticamente parâmetros de rota Flask como fontes. Não decide vulnerabilidade — quem interpreta as procedências é o detector, que conhece a CWE |
| Dependências | `analisador.ArquivoAnalisado`, `motor.catalogo` |
| Utilizado por | `varredura` e quase todos os detectores |

Helpers públicos: `nos_do_escopo` (nós do escopo sem descer em escopos aninhados — evita achados duplicados), `literais_de_string` (resolve constantes de expressões para inspeção de queries), `escopo_de`, `parametros_de_rota_por_escopo`.

### Catálogo (dados declarativos)

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/motor/catalogo.py` (886 linhas, maior arquivo do projeto) |
| Responsabilidade | **Dado, não lógica.** Fontes não confiáveis (`FonteDeDados`: `request.args`, `request.form`, parâmetro de rota, etc.), sinks (`SinkSql` DB-API 2.0, `SinkXss`, `SinkDeArgumento` genérico com posições/palavras-chave), `Sanitizador` (cada um declara **quais CWEs neutraliza** — `int()` defende CWE-89/79; `html.escape()` defende CWE-79 e não CWE-89), e o índice consultável `Catalogo` com instância global `CATALOGO_PADRAO`. Inclui consultas de framework: `e_view_de_rota`, `tem_decorador_de_autorizacao`, `nomes_de_parametros_de_rota`, `nome_pontilhado` |
| Dependências | stdlib (`ast`, `dataclasses`) |
| Utilizado por | `motor.taint`, `varredura`, `detectores/comum.py` e quase todos os detectores |

Adicionar suporte a um framework = acrescentar entradas aqui, **sem tocar em `taint.py`**.

### Consultas Estruturais

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/motor/estrutura.py` |
| Responsabilidade | Responder "como este código está montado" (complemento ao taint, que responde "de onde veio este valor"): `mapa_de_importacoes`, `nome_qualificado`, `valor_constante`, `atribuicoes_de_configuracao`, `nomes_de_decoradores`, `metodos_http`, `caminhos_da_rota`, `funcoes_de_rota`, `tokens_de_nome`. Tudo leitura de AST, sem regex |
| Utilizado por | detectores estruturais/heurísticos (xxe, csrf, autorizacao, autenticacao, path_traversal, open_redirect, credenciais) e `detectores/comum.py` |

### Regras de Credenciais

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/motor/credenciais.py` |
| Responsabilidade | Regras compartilhadas do CWE-798, usadas tanto no código Python (via AST) quanto em arquivos de configuração. Decisão em duas metades independentes: o **nome** designa credencial (`nomeia_credencial`, com exceções para metadados como `token_url`) e o **valor** é segredo plausível (`e_segredo_plausivel`), não placeholder (`${VAR}`, `<sua-chave>`) nem referência (`parece_referencia`). Inclui `url_com_senha` e `mascarar` — **o relatório mascara o segredo**: "a ferramenta não pode ser o vazamento que denuncia" |
| Utilizado por | `detectores/credenciais.py`, `detectores/autenticacao.py` (senha em texto puro) |

### Calibração de Confiança

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/motor/confianca.py` |
| Responsabilidade | `confianca` descreve a cadeia fonte→sink, não a gravidade da CWE: **alta** (operacões de string diretas, fluxo incondicional), **média** (passou por função não analisada ou ramo condicional), **baixa** (reservada a heurísticas). `procedencias_relevantes` filtra procedências pela CWE em jogo; `justificativa` explica o nível. Sanitização que neutraliza a CWE **remove** o achado — não rebaixa confiança |
| Dependências | `motor.taint.Procedencia` |
| Utilizado por | detectores de taint (sqli, xss, idor, xxe, path_traversal, open_redirect) e `autenticacao.py` |

### Detectores

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/detectores/` (11 módulos) |
| Responsabilidade | Interpretar os escopos do taint e/ou a estrutura da AST e emitir `list[Achado]` via `criar_achado`. Um detector não anda na AST por conta própria nem decide classificação (contrato em `base.py`: Protocol `Detector` com `detectar(arquivo, escopos)`) |
| Utilizados por | `varredura.detectores_padrao()` |

| Módulo | CWEs | Técnica |
| --- | --- | --- |
| `base.py` | — | Protocol `Detector` + `ordenar_achados` |
| `comum.py` | — | helpers de sink por argumento (`casar_sink`, `argumentos_do_sink`, `testes_de_condicao`, guardas) |
| `sqli.py` | 89 | taint → sinks DB-API 2.0 |
| `xss.py` | 79 | taint → sinks de resposta HTML (`render_template` é caminho seguro pelo auto-escape) |
| `idor.py` | 639 | heurística — reporta **candidatos** (confiança sempre baixa); suprimido por filtro de dono na query ou decorator de autorização; `@login_required` não suprime |
| `path_traversal.py` | 22 | taint + guardas (`realpath`+`startswith`, `secure_filename`) |
| `open_redirect.py` | 601 | taint + guardas (`url_has_allowed_host_and_scheme`, `url_for`) |
| `xxe.py` | 611 | estrutural + taint (lxml/SAX; stdlib `xml.etree`/`minidom`/`sax` não são acusados — não resolvem entidades desde Python 3.7.1) |
| `csrf.py` | 352 | estrutural/heurística (`@csrf_exempt` = alta; app Flask sem `CSRFProtect` = candidata) |
| `autorizacao.py` | 862 | heurística (rota que altera estado sem decorator/checagem; `/admin` exige papel; rotas públicas por natureza ignoradas; `before_request` suprime) |
| `autenticacao.py` | 287, 916, 256, 614, 1004, 613, 307 | 6 detectores: JWT sem verificação, hash fraco de senha, senha em texto puro, cookies sem Secure/HttpOnly, expiração de sessão, login sem rate limit |
| `credenciais.py` | 798 | 2 detectores: no código Python (AST) e em arquivos de configuração (recebe `ArquivoDeConfiguracao` direto da varredura, fora do fluxo de escopos) |

### Leitor de Configuração

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/configuracao.py` |
| Responsabilidade | Exceção declarada ao princípio "somente AST": lê arquivos não-Python em busca de credenciais fixas. JSON via parser da stdlib; `.env`/`.properties`/INI/TOML por gramática de linha `chave = valor`; YAML por pares `chave: valor` e itens `- CHAVE=valor` (limitação declarada: escalares de bloco, multi-linha e âncoras não são interpretados). Produz `ArquivoDeConfiguracao`/`EntradaDeConfiguracao`. Arquivos-modelo (`.env.example`) saem com severidade baixa. Teto de 1 MB |
| Utilizado por | `varredura`, `api` (`formato_de`), `metricas` |

### Relatório

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/relatorio.py` |
| Responsabilidade | Módulo **puro** (não lê arquivos nem executa detectores — saída determinística e testável sem disco). `formatar_texto()`: resumo executivo para terminal com contagens, seções separadas "ACHADOS RASTREADOS POR TAINT" e "CANDIDATOS HEURISTICOS (requerem revisão manual)", recomendações por CWE e arquivos não analisados. `para_dict()`: estrutura JSON com metadados de execução (rastreabilidade: sem saber quantos arquivos falharam, as métricas perdem o denominador) |
| Utiliza | `achado`, `varredura` (reexporta `Varredura`) |
| Utilizado por | `cli.py`, `api.py` |

O corte entre seções é `confianca == "baixa"`, não a CWE: qualquer detector heurístico futuro cai na seção certa sem mudar este módulo.

### Métricas (autoavaliação)

| | |
| --- | --- |
| Localização | `TOOL/owaspscan/metricas.py` + corpus `TOOL/tests/amostras/` |
| Responsabilidade | `python -m owaspscan.metricas caminho`: carrega o gabarito embutido nas próprias amostras (comentários `# achado: CWE-x` na linha do sink e `# limitacao: CWE-x ...`), roda `executar()` e calcula VP/FP/FN, precisão, recall e F1 por CWE. **Limitação declarada conta como falso negativo** — "declarar a falha não a transforma em acerto" |
| Utiliza | `achado` (MAPA), `configuracao`, `varredura` |
| Utilizado por | equipe (avaliação contínua) e `tests/conftest.py` (`linhas_esperadas`, `linhas_de_limitacao`, `rodar_detector`) |

Resultado declarado no `TOOL/README.md`: precisão 1.00, recall 0.98, F1 0.99 sobre corpus próprio de 25 arquivos Python + 9 de configuração. Limite de validade declarado: corpus pequeno construído junto com a ferramenta — mede consistência interna, não generalização.

### Frontend (protótipo)

| | |
| --- | --- |
| Localização | `frontend/` |
| Responsabilidade | SPA React de página única. `main.jsx` monta `<App/>`; `App.jsx` (382 linhas, arquivo único) concentra: navegação por estado (`paginaAtual`), tema dark/light persistido em `localStorage` (chave `aegis-tema`), i18n pt/en (`translate.js`), abas de análise (file/url/snippet/cli), drag & drop de arquivos, páginas estáticas (docs, termos, privacidade, FAQ, scripts) com texto hardcoded |
| Dependências | react/react-dom 19; build: Vite 8, Tailwind 3.4, PostCSS, Oxlint |
| Integração | **Nenhuma.** Arquivos enviados ficam apenas no `useState`; nenhum `fetch` no código. Os textos exibidos descrevem funcionalidades que não existem (análise de malware/URLs/domínios, múltiplas linguagens, `npm install -g @aegis/cli`, API `https://api.aegis.dev/v1`) |

O contrato de integração futuro já está definido no `TOOL/README.md` (seção "API HTTP (para o site)"): `POST /analisar` com JSON ou FormData — a API foi construída para o frontend, que ainda não a consome.

### Testes

| | |
| --- | --- |
| Localização | `TOOL/tests/` (19 arquivos, ~336 funções `test_*`) |
| Responsabilidade | Cobrem todas as camadas: contrato, analisador, taint (38 testes), sanitização, cada detector, relatório, configuração, API (26 testes), integração ponta-a-ponta e métricas. `conftest.py` expõe atalhos de gabarito. `tests/amostras/` é o corpus rotulado (vulneravel/, seguro/, analisador/, config/) — as amostras de `seguro/` são seguras **para a CWE que nomeiam**, não para todas |
| Execução | `.venv/bin/python -m pytest -v` em `TOOL/` |
| Lacuna | Frontend sem nenhum teste |

## Fluxos de dados

### Fluxo 1 — Análise via CLI

```
Desenvolvedor/CI
  ↓ argv: caminho [--json]
cli.main()                                    (cli.py:52)
  ↓ Path
varredura.executar(raiz)                      (varredura.py:92)
  ├→ analisador.analisar_diretorio()          → [ArquivoAnalisado] + [FalhaDeLeitura]
  ├→ para cada arquivo:
  │    taint.analisar_taint(arquivo)          → [Escopo] (contaminados + Procedencia)
  │    15× detector.detectar(arquivo, escopos)→ [Achado]
  └→ configuracao.ler_diretorio()             → [ArquivoDeConfiguracao]
       DetectorCredenciaisEmConfiguracao      → [Achado] (segredo mascarado)
  ↓ Varredura (achados ordenados por arquivo/linha/CWE)
relatorio.formatar_texto() / para_dict()
  ↓ stdout (texto)  ou  JSON→stdout + resumo→stderr (--json)
exit code: 0 (sem achado alto) · 1 (com achado alto) · 2 (erro de uso)
```

Entrada: caminho de arquivo `.py`, arquivo de configuração ou diretório. Saída: relatório texto ou JSON no terminal + código de saída para automação.

### Fluxo 2 — Análise via API HTTP

```
Cliente HTTP
  ↓ POST /analisar  (application/json OU multipart/form-data)
api.analisar()                                (api.py:191)
  ↓ dispatch por Content-Type (senão 415)
_envios_de_json / _envios_de_formulario
  ↓ montar_envios(): nome-base, formato aceito, duplicatas,
    ≤50 arquivos, ≤1 MB cada       (erros 400/413/422)
run_in_threadpool(varrer)                     (api.py:199-200)
  ↓ tempfile.TemporaryDirectory → grava bytes → executar() → para_dict()
    (raiz exibida = "envio"; pasta destruída ao final da requisição)
  ↓ resposta JSON = mesmo contrato do --json
GET /saude → {"status":"ok","versao":"0.2.0"}  ·  /docs → OpenAPI
```

Entrada: `{"codigo": "...", "nome": "app.py", "arquivos": [{"nome","conteudo"}]}` ou form-data com campos `codigo`, `nome`, `arquivos` (repetível). Saída: JSON da varredura. Erros: `{"detail": "..."}`.

### Fluxo 3 — Avaliação (métricas)

```
python -m owaspscan.metricas tests/amostras
  ↓ carregar_gabarito() — comentários "# achado:" / "# limitacao:" nas amostras
  ↓ varredura.executar(corpus)
  ↓ confronto achados × gabarito → VP/FP/FN por CWE
  ↓ formatar_tabela() → stdout (precisão/recall/F1)
```

### Fluxo 4 — Frontend (estado atual, incompleto)

```
Usuário → index.html → main.jsx → App.jsx
  ↓ interações locais: tema (localStorage), idioma, abas, drag&drop
  ✗ arquivos ficam apenas no useState — nenhuma chamada de rede
```

## Integrações

- **APIs do projeto**: somente a API FastAPI do `TOOL` (`POST /analisar`, `GET /saude`, OpenAPI em `/docs`).
- **Banco de dados**: nenhum. Nenhuma persistência em lugar algum.
- **Serviços externos**: nenhum. O núcleo é 100% offline (stdlib); a API só recebe requisições, não faz chamadas externas.
- **Plataformas institucionais**: nenhuma integração de código; GitHub é usado apenas para gestão (issue/PR templates em `.github/`, sem workflows).

## Dados e armazenamento

| Dado | Origem | Circulação | Destino |
| --- | --- | --- | --- |
| Código analisado (CLI) | disco local do usuário | lido → parseado em memória → nunca executado | relatório no stdout; nada retido |
| Código analisado (API) | upload/JSON do cliente | `TemporaryDirectory` → bytes em disco temporário → `executar()` → pasta destruída | resposta JSON; nada persistido |
| Segredos encontrados | código/configuração analisados | detectados via AST/parsers | **mascarados** no relatório (`motor/credenciais.mascarar`) |
| Achados | detectores | memória (tuplas imutáveis) | stdout/resposta HTTP; `.gitignore` do TOOL exclui `relatorio.json` |
| Tema do usuário web | navegador | — | `localStorage` (chave `aegis-tema`) |

Privacidade: o frontend afirma em texto estático que nada é armazenado — coerente com o comportamento real da API (efêmero por requisição), mas não há documento formal de tratamento de dados.

## Decisões técnicas

Registradas em `TOOL/CLAUDE.md`, docstrings e READMEs (ainda sem ADRs formais em `docs/decisoes/`):

1. **Stdlib-only no núcleo** — sem dependências pesadas; FastAPI isolado como extra `[api]` para o scanner nunca depender de framework web.
2. **AST, nunca regex** — com exceção declarada e delimitada para arquivos de configuração não-Python.
3. **Mapa CWE→OWASP canônico e fechado** — imposto por `criar_achado`/`__post_init__`; `test_contrato.py` impede classificação inventada.
4. **Catálogo é dado, motor é lógica** — novo framework = novas entradas em `catalogo.py`, sem tocar em `taint.py`.
5. **Confiança calibrada > cobertura inflada** — heurísticas reportam candidatos (confiança baixa, descrição "Candidato a..."), não afirmações; candidatos não quebram build.
6. **Pessimismo em chamadas desconhecidas** — falso positivo preferido a falso negativo silencioso.
7. **Sanitização por CWE** — cada sanitizador declara o que neutraliza; tratar sanitização como absoluta seria falso negativo.
8. **Mascaramento de segredos no relatório** — a ferramenta não pode ser o vazamento que denuncia.
9. **Gabarito embutido no corpus** — avaliação reprodutível; limitação declarada conta como FN.
10. **Relatório puro vs. orquestração com I/O** — separação `varredura.py`/`relatorio.py` para saída determinística e testável.
11. **Desenvolvimento em fases** — 19 fases commitadas individualmente (histórico git), cada uma com testes.

## Segurança da própria ferramenta

- **Autenticação**: nenhuma. A API é aberta.
- **Autorização**: nenhuma; único controle de acesso é CORS via `OWASPSCAN_ORIGENS` (padrão `*`).
- **Superfície de ataque da API**: entrada hostil por definição, mitigada por validação de nomes (nome-base), tipo de arquivo, tamanho (1 MB) e quantidade (50); o código enviado nunca é executado, só parseado; a pasta temporária é destruída por requisição.
- **Vazamento**: segredos detectados são mascarados na saída.
- **Riscos remanescentes**: API sem auth nem rate limit se exposta fora de localhost; `ast.parse` de entrada hostil é seguro quanto a execução, mas não há limite de complexidade/tempo de análise por requisição.

## Configuração e infraestrutura

**Configuração existente:**

| Arquivo | Papel |
| --- | --- |
| `TOOL/pyproject.toml` | Pacote `owaspscan` 0.2.0; extras `api` (fastapi, uvicorn, python-multipart) e `dev` (pytest, httpx); pytest config (`testpaths`, `-q`) |
| Variáveis de ambiente | `OWASPSCAN_HOST`, `OWASPSCAN_PORTA`, `OWASPSCAN_ORIGENS` — somente na API |
| `frontend/package.json` | scripts `dev`/`build`/`lint`/`preview`; React 19, Vite 8, Tailwind 3.4, Oxlint |
| `frontend/vite.config.js`, `tailwind.config.js`, `postcss.config.js`, `.oxlintrc.json` | Build e lint do frontend; sem proxy/env configurado para a API |
| `.editorconfig`, `.markdownlint.json`, `.gitignore` (raiz/TOOL/frontend) | Padrões de editor, lint de markdown, exclusões |

**Infraestrutura: inexistente.** Sem Dockerfile, sem docker-compose de deploy (os `docker-compose.yml` em `TOOL/tests/amostras/*/config/` são fixtures de teste do detector de credenciais), sem `.github/workflows/` (CI/CD), sem IaC. Execução 100% local: venv + `python -m owaspscan` / `python -m owaspscan.api` / `npm run dev`.

**Logs/monitoramento**: nenhum mecanismo próprio; stdout/stderr (CLI) e logs padrão do Uvicorn (API); `GET /saude` é o único healthcheck.

## Riscos e lacunas arquiteturais

1. **Frontend desconectado**: a API foi construída explicitamente "para o site" (Fases 18-19), mas o frontend não faz nenhuma chamada de rede; abas URL/Snippet/Upload não produzem efeito.
2. **Frontend descreve produto diferente**: textos de `translate.js`/`App.jsx` prometem análise de malware/URLs/domínios/IPs, suporte a JavaScript/PHP/C++, CLI npm `@aegis/cli` e API `api.aegis.dev` — nada disso existe; o motor analisa somente Python/configuração.
3. **Identidade dupla**: README raiz ("AEGIS-CODE", com pre-commit hook e bloqueio de merge em CI) vs `TOOL/README.md` ("OWASP-Scan", iniciação científica). Hook de pre-commit e integração de CI citados no README raiz não estão implementados.
4. **API sem autenticação nem rate limit** — aceitável em localhost, não em deployment público.
5. **Sem CI/CD** — os ~336 testes só rodam localmente.
6. **Documentação de gestão vazia** — `docs/requisitos.md` segue template, CHANGELOG para na Sprint 00 apesar de 19 fases, `TOOL/README.md` lista "Estado" até a Fase 16 (git mostra Fase 19), LICENSE é placeholder institucional.
7. **Sem testes de frontend** e UI inteira em um único arquivo de 382 linhas.
8. **Limitações do motor** (intraprocedural, insensível a fluxo, cego a templates) são conhecidas, declaradas e medidas como FN pela avaliação — não são defeitos ocultos, mas restringem o uso como única barreira de segurança.

## Diagramas e relação com ADRs

Os diagramas deste documento são ASCII e derivados diretamente do código. Decisões técnicas relevantes (stdlib-only, API como extra, sem banco de dados, sem persistência) ainda não possuem ADRs formais — a pasta `docs/decisoes/` contém apenas o template. Recomenda-se registrar como ADR ao menos: (1) núcleo sem dependências, (2) taint intraprocedural com limitações declaradas, (3) ausência de persistência/banco, (4) API sem autenticação no escopo atual.
