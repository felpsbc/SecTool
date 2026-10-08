# Estrutura de arquivos

Inventário técnico do repositório AEGIS: organização de diretórios, papel de cada arquivo relevante, grafo de dependências e trilha de leitura recomendada. Baseado exclusivamente no código existente (commit `a90120a`). Arquivos irrelevantes para compreensão (caches, `node_modules`, gerados, `package-lock.json`, binários e assets) estão listados na seção [Exclusões](#exclusões).

## Visão geral da organização

```
AEGIS/
├── README.md                  # identificação, problema e solução (institucional)
├── SECURITY.md                # política de segredos e incidentes
├── CHANGELOG.md               # histórico (parado na Sprint 00)
├── CONTRIBUTING.md            # guia de contribuição (template)
├── CODE_OF_CONDUCT.md         # código de conduta (template)
├── LICENSE                    # placeholder institucional (sem licença efetiva)
├── Artigo_Vulnerabilidades_Codigo_IA.pdf   # artigo acadêmico de referência
├── .editorconfig / .markdownlint.json / .gitignore   # padrões globais
│
├── TOOL/                      # ★ O PRODUTO: motor SAST "owaspscan" (Python)
│   ├── README.md              # documentação técnica principal (cobertura, limitações, avaliação)
│   ├── CLAUDE.md              # princípios de desenvolvimento inegociáveis
│   ├── pyproject.toml         # pacote, extras [api]/[dev], config do pytest
│   ├── owaspscan/             # código-fonte (camadas: contrato→AST→motor→detectores→saída→entradas)
│   │   ├── achado.py          # contrato central de achado + mapa CWE→OWASP
│   │   ├── analisador.py      # camada AST (descoberta, parse resiliente, localização)
│   │   ├── configuracao.py    # leitores de .env/YAML/JSON/INI/TOML/.properties
│   │   ├── varredura.py       # orquestração do pipeline
│   │   ├── relatorio.py       # formatação pura (texto/JSON)
│   │   ├── cli.py             # entrada de linha de comando
│   │   ├── api.py             # entrada HTTP (FastAPI, extra opcional)
│   │   ├── metricas.py        # autoavaliação contra corpus rotulado
│   │   ├── __main__.py        # python -m owaspscan
│   │   ├── motor/             # mecânica de análise reutilizável
│   │   │   ├── catalogo.py    # fontes/sinks/sanitizadores (dado declarativo)
│   │   │   ├── taint.py       # motor de taint intraprocedural
│   │   │   ├── estrutura.py   # consultas estruturais sobre a AST
│   │   │   ├── credenciais.py # regras de reconhecimento de segredos (CWE-798)
│   │   │   └── confianca.py   # calibração alta/média/baixa
│   │   └── detectores/        # 11 módulos, 16 CWEs
│   │       ├── base.py        # Protocol Detector + ordenação
│   │       ├── comum.py       # helpers de sink por argumento
│   │       ├── sqli.py  xss.py  idor.py  xxe.py
│   │       ├── path_traversal.py  open_redirect.py  csrf.py
│   │       ├── autorizacao.py  autenticacao.py  credenciais.py
│   └── tests/                 # pytest (~336 testes) + corpus rotulado
│       ├── conftest.py        # atalhos de gabarito para os testes
│       ├── test_*.py          # 19 arquivos, um por camada/detector
│       └── amostras/          # corpus de avaliação (vulneravel/, seguro/, analisador/, config/)
│
├── frontend/                  # SPA React/Vite/Tailwind — protótipo visual (não chama a API)
│   ├── package.json / vite.config.js / tailwind.config.js / postcss.config.js / .oxlintrc.json
│   ├── index.html             # shell HTML (favicon inline, #root)
│   ├── public/                # favicon.svg, icons.svg
│   └── src/
│       ├── main.jsx           # bootstrap React
│       ├── App.jsx            # UI inteira (382 linhas, arquivo único)
│       ├── translate.js       # dicionário i18n pt/en
│       ├── index.css          # diretivas Tailwind
│       ├── App.css            # vazio
│       └── assets/            # imagens (hero.png, logos)
│
├── docs/                      # documentação do projeto
│   ├── arquitetura.md         # ★ arquitetura real (preenchido)
│   ├── estrutura.md           # ★ este documento
│   ├── requisitos.md          # template genérico (não preenchido)
│   ├── decisoes/              # ADRs — apenas README + template
│   └── reunioes/              # atas — apenas README + template
│
├── sprints/                   # registros de sprint (sprint-00 = template; README; template)
├── entregas/                  # entregas avaliativas (README, template, fontes/equipe)
└── .github/                   # templates de issue (bug/requisito/documentacao/pesquisa/config)
                               # e de PR — sem workflows (não há CI/CD)
```

## Finalidade dos diretórios

| Diretório | Finalidade |
| --- | --- |
| `TOOL/` | Produto principal: analisador estático (SAST) de vulnerabilidades OWASP Top 10:2021 em código Python (Django/Flask) e arquivos de configuração. Autocontido: núcleo só com stdlib. |
| `TOOL/owaspscan/` | Pacote Python em camadas, com dependências unidirecionais (contrato → AST → motor → detectores → orquestração → saída → entradas). |
| `TOOL/owaspscan/motor/` | Mecânica de análise compartilhada: o que é "dado de onde veio" (taint), "o que é perigoso" (catálogo), "como o código está montado" (estrutura), "isso é um segredo?" (credenciais) e "quanto confio?" (confianca). |
| `TOOL/owaspscan/detectores/` | Uma CWE (ou família) por módulo. Todo detector recebe `ArquivoAnalisado` + `Escopo`s prontos e devolve `Achado`s — nunca anda na AST por conta própria nem inventa classificação. |
| `TOOL/tests/` | Suíte pytest por camada/detector + `amostras/`, que serve a dois propósitos: fixtures de teste e corpus de avaliação com gabarito embutido em comentários (`# achado: CWE-x` / `# limitacao: CWE-x`). |
| `frontend/` | Interface web do produto (React 19 + Vite 8 + Tailwind 3.4). Estado atual: protótipo de UI — tema dark/light, i18n pt/en, abas arquivo/URL/código/CLI, drag & drop — **sem nenhuma chamada de rede**; a integração prevista é `POST /analisar` da API do TOOL. |
| `docs/` | Documentação técnica e de gestão do projeto acadêmico. |
| `sprints/` · `entregas/` · `.github/` | Gestão da disciplina: ciclos de sprint, evidências de entrega e padronização de issues/PRs. |

## Fichas dos arquivos relevantes

Legenda: **Depende de** = imports internos do pacote; **Dependentes** = quem o importa.

### Núcleo — contrato e AST

#### `TOOL/owaspscan/achado.py` (218 linhas)

- **Função**: contrato interno de achado — o tipo que atravessa todo o sistema.
- **Responsabilidade**: definir `Achado` (10 campos fixos), o mapa canônico `MAPA_CWE_OWASP` (16 CWEs) e a fábrica `criar_achado()` que deriva `owasp`/`vulnerabilidade` do mapa, impedindo classificação inventada; validar tudo no `__post_init__`.
- **Principais classes/funções**: `ClasseVulnerabilidade`, `MAPA_CWE_OWASP`, `CAMPOS_CONTRATO`, `ClassificacaoInvalida`, `Achado`, `criar_achado()`, `campos_do_achado()`.
- **Dependências**: stdlib apenas (`dataclasses`, `typing`).
- **Depende de**: nada — é a base do sistema.
- **Dependentes**: todos os 11 módulos de `detectores/`, `relatorio.py`, `metricas.py`, `tests/test_contrato.py` (protege o mapa) e `tests/test_relatorio.py`.

#### `TOOL/owaspscan/analisador.py` (183 linhas)

- **Função**: camada AST — "não sabe nada sobre vulnerabilidades".
- **Responsabilidade**: descobrir arquivos `.py` (ordem estável, pulando diretórios de build/venv), parsear com resiliência (`tokenize.open` + `ast.parse`; falhas viram dado, não exceção) e localizar nós (linha, trecho normalizado ≤120 chars).
- **Principais classes/funções**: `DIRETORIOS_IGNORADOS`, `FalhaDeLeitura`, `ArquivoAnalisado` (`linha_de`, `trecho_de`), `normalizar_trecho()`, `caminho_relativo()`, `descobrir_arquivos()`, `analisar_arquivo()`, `analisar_diretorio()`, `analisar_texto()`.
- **Dependências**: stdlib (`ast`, `tokenize`, `dataclasses`, `pathlib`).
- **Depende de**: nada.
- **Dependentes**: `motor/taint.py`, `configuracao.py` (reutiliza `DIRETORIOS_IGNORADOS`, `FalhaDeLeitura`, `caminho_relativo`), `varredura.py`, `detectores/base.py`, todos os detectores (tipo `ArquivoAnalisado`), `tests/`.

### Núcleo — motor (`TOOL/owaspscan/motor/`)

#### `motor/catalogo.py` (886 linhas — maior arquivo do projeto)

- **Função**: catálogo declarativo de fontes, sinks e sanitizadores — **dado, não lógica**.
- **Responsabilidade**: centralizar o conhecimento de frameworks (Flask/Django/DB-API/lxml/bcrypt...): fontes não confiáveis, sinks por categoria, sanitizadores com as CWEs que neutralizam, e consultas de framework (view de rota, decorator de autorização, parâmetros de rota). Ponto de extensão: novo framework = novas entradas aqui, sem tocar em `taint.py`.
- **Principais classes/funções**: `FonteDeDados`, `SinkSql`, `Sanitizador`, `SinkXss`, `SinkDeArgumento`, `Catalogo`, `CATALOGO_PADRAO`, `nome_pontilhado()`, `e_view_de_rota()`, `tem_decorador_de_autorizacao()`, `nomes_de_parametros_de_rota()`.
- **Dependências**: stdlib (`ast`, `dataclasses`).
- **Depende de**: nada.
- **Dependentes**: `motor/taint.py`, `motor/estrutura.py`, `motor/confianca.py`, `varredura.py`, `detectores/comum.py` e 9 dos 11 detectores.

#### `motor/taint.py` (414 linhas)

- **Função**: motor de taint tracking intraprocedural e insensível a fluxo.
- **Responsabilidade**: para cada módulo/classe/função, produzir um `Escopo` com nomes contaminados → `Procedencia` (fonte, sanitizadores no caminho, `via_chamada`, `condicional`), propagando por ponto fixo (independente da ordem textual). Não decide vulnerabilidade — devolve procedências para os detectores interpretarem. Semeia parâmetros de rota Flask como fontes.
- **Principais classes/funções**: `Procedencia`, `Escopo` (`esta_contaminado`, `procedencias_de`, `expressao_contaminada`), `analisar_taint()`, `parametros_de_rota_por_escopo()`, `escopo_de()`, `nos_do_escopo()`, `literais_de_string()`.
- **Dependências**: stdlib (`ast`, `dataclasses`).
- **Depende de**: `analisador.py`, `motor/catalogo.py`.
- **Dependentes**: `motor/confianca.py`, `varredura.py`, `detectores/base.py`, `detectores/comum.py`, quase todos os detectores, `tests/test_taint.py` (38 testes), `tests/conftest.py`.

#### `motor/estrutura.py` (246 linhas)

- **Função**: consultas estruturais sobre a AST — "como este código está montado".
- **Responsabilidade**: responder o que o taint não responde: imports e nomes qualificados, valores constantes, atribuições de configuração, decorators, métodos HTTP e caminhos de rotas, tokenização de identificadores. Tudo leitura de AST, sem regex.
- **Principais classes/funções**: `mapa_de_importacoes()`, `nome_qualificado()`, `valor_constante()`, `argumento()`, `AtribuicaoDeConfiguracao`, `atribuicoes_de_configuracao()`, `nomes_de_decoradores()`, `metodos_http()`, `caminhos_da_rota()`, `funcoes_de_rota()`, `tokens_de_nome()`.
- **Dependências**: stdlib (`ast`, `dataclasses`, `typing`).
- **Depende de**: `motor/catalogo.py` (`e_view_de_rota`, `nome_pontilhado`).
- **Dependentes**: `motor/credenciais.py`, `detectores/comum.py`, `detectores/xxe.py`, `csrf.py`, `autorizacao.py`, `autenticacao.py`, `path_traversal.py`, `open_redirect.py`, `credenciais.py`, `tests/test_estrutura.py`.

#### `motor/credenciais.py` (251 linhas)

- **Função**: regras compartilhadas de reconhecimento de segredos (CWE-798).
- **Responsabilidade**: decidir em duas metades independentes — o **nome** designa credencial (com exceções para metadados como `token_url`) e o **valor** é segredo plausível (não placeholder `${VAR}` nem referência). Usado tanto no código Python (AST) quanto em arquivos de configuração. Inclui o mascaramento: o relatório nunca expõe o segredo inteiro.
- **Principais classes/funções**: `nomeia_credencial()`, `e_placeholder()`, `parece_referencia()`, `e_segredo_plausivel()`, `url_com_senha()`, `mascarar()`.
- **Dependências**: stdlib (`urllib.parse`).
- **Depende de**: `motor/estrutura.py` (`tokens_de_nome`).
- **Dependentes**: `detectores/credenciais.py`, `detectores/autenticacao.py` (senha em texto puro), `tests/test_credenciais.py`.

#### `motor/confianca.py` (48 linhas)

- **Função**: calibração do campo `confianca` do achado.
- **Responsabilidade**: converter `Procedencia`s em nível (alta = string direta em fluxo incondicional; média = passou por função não analisada ou ramo condicional) e gerar justificativa textual. `procedencias_relevantes()` filtra pela CWE em jogo — sanitização que neutraliza a CWE **remove** o achado, não rebaixa confiança.
- **Principais classes/funções**: `procedencias_relevantes()`, `confianca_para()`, `justificativa()`.
- **Dependências**: nenhuma externa.
- **Depende de**: `motor/catalogo.py` (`Catalogo`), `motor/taint.py` (`Procedencia`).
- **Dependentes**: detectores de taint (`sqli`, `xss`, `idor`, `xxe`, `path_traversal`, `open_redirect`) e `detectores/autenticacao.py`.

### Núcleo — detectores (`TOOL/owaspscan/detectores/`)

#### `detectores/base.py` (30 linhas)

- **Função**: contrato comum dos detectores.
- **Responsabilidade**: definir o Protocol `Detector` (`nome`, `cwe`, `detectar(arquivo, escopos) -> list[Achado]`) e a ordenação estável de relatório.
- **Principais classes/funções**: `Detector` (Protocol), `ordenar_achados()`.
- **Depende de**: `achado.py`, `analisador.py`, `motor/taint.py` (tipos).
- **Dependentes**: `varredura.py` (tipagem e ordenação); conceitualmente, todos os detectores o seguem.

#### `detectores/comum.py` (49 linhas)

- **Função**: peças compartilhadas pelos detectores de taint com sinks por argumento.
- **Responsabilidade**: casar chamadas AST com sinks declarados (`casar_sink`), extrair os argumentos nas posições/palavras-chave do sink, levantar condições usadas como guardas e nomes contaminados numa expressão.
- **Principais funções**: `casar_sink()`, `argumentos_do_sink()`, `testes_de_condicao()`, `nomes_contaminados_em()`.
- **Depende de**: `motor/catalogo.py`, `motor/estrutura.py`, `motor/taint.py`.
- **Dependentes**: `detectores/path_traversal.py`, `detectores/open_redirect.py`.

#### `detectores/sqli.py` (79 linhas)

- **Função**: detector de SQL Injection (CWE-89) — o mais simples e melhor exemplo do padrão taint.
- **Responsabilidade**: percorrer `nos_do_escopo`, casar chamadas com `SinkSql` do catálogo (DB-API 2.0: `execute`, `executemany`, `raw`, `extra`...) e verificar contaminação dos argumentos; sanitização relevante remove o achado; confiança via `motor/confianca`.
- **Principais classes/funções**: `DetectorSqlInjection`, `_descricao()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/confianca`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_sqli.py`.

#### `detectores/xss.py` (128 linhas)

- **Função**: Cross-Site Scripting refletido (CWE-79).
- **Responsabilidade**: taint até sinks de resposta HTML (`SinkXss`); `render_template` é caminho seguro (auto-escape do Jinja2); limitado a código Python — templates `.html` são ponto cego declarado.
- **Principais classes/funções**: `DetectorXss`, `_descricao()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo` (`e_view_de_rota`), `motor/confianca`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_xss.py`.

#### `detectores/idor.py` (160 linhas)

- **Função**: IDOR (CWE-639) — **heurístico, reporta candidatos**.
- **Responsabilidade**: identificar views que recebem identificador da rota/request e consultam objeto sem filtro de dono; confiança sempre `baixa`, descrição sempre "Candidato a IDOR (requer revisão manual)". Suprimido por filtro de dono na query (`filter_by(id=pid, user=current_user)`) ou decorator de autorização; `@login_required` **não** suprime (autenticar ≠ autorizar).
- **Principais classes/funções**: `DetectorIdor`, `PREFIXO_CANDIDATO`, `_compara_campo_de_dono()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/confianca`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_idor.py`.

#### `detectores/xxe.py` (239 linhas)

- **Função**: XML External Entity (CWE-611).
- **Responsabilidade**: estrutural + taint em lxml/SAX: parser configurado para resolver entidades (alta confiança) ou recebendo dado da requisição com parser padrão (média — comportamento do lxml mudou na v5.0, invisível à análise). `xml.etree`/`minidom`/`xml.sax` da stdlib **não** são acusados (não resolvem entidades desde Python 3.7.1).
- **Principais classes/funções**: `DetectorXxe`, `motivo_de_parser_inseguro()`, `_e_parser_seguro()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/confianca`, `motor/estrutura`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_xxe.py`.

#### `detectores/path_traversal.py` (177 linhas)

- **Função**: Path Traversal (CWE-22) por taint + guardas.
- **Responsabilidade**: taint até sinks de abertura/manipulação de caminho; suprime quando há guarda no escopo (canonicalização `realpath` + `startswith`, ou `secure_filename` — que defende só CWE-22). Guardas são insensíveis a fluxo (limitação declarada).
- **Principais classes/funções**: `DetectorPathTraversal`, `nomes_confinados()`, `_contem_canonicalizacao()`, `_ultimo_nome()`.
- **Depende de**: `achado`, `analisador`, `detectores/comum`, `motor/catalogo`, `motor/confianca`, `motor/estrutura`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_path_traversal.py`.

#### `detectores/open_redirect.py` (138 linhas)

- **Função**: Open Redirect (CWE-601) por taint + guardas.
- **Responsabilidade**: taint até `redirect()`/`RedirectResponse` etc.; suprime com validação de host (`url_has_allowed_host_and_scheme`) ou destino gerado por `url_for` (defende só CWE-601).
- **Principais classes/funções**: `DetectorOpenRedirect`, `nomes_validados()`.
- **Depende de**: `achado`, `analisador`, `detectores/comum`, `motor/catalogo`, `motor/confianca`, `motor/estrutura`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_open_redirect.py`.

#### `detectores/csrf.py` (211 linhas)

- **Função**: CSRF (CWE-352) — estrutural e heurístico.
- **Responsabilidade**: `@csrf_exempt` explícito (confiança alta) e app Flask com rota que altera estado sem `CSRFProtect`/`FlaskForm` no arquivo (candidato — a proteção pode estar em outro módulo). Rotas com `@jwt_required` não contam.
- **Principais classes/funções**: `DetectorCsrf`, `_e_exempt()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/estrutura`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_csrf_autorizacao.py`.

#### `detectores/autorizacao.py` (150 linhas)

- **Função**: rota sem autorização (CWE-862) — heurístico, candidatos.
- **Responsabilidade**: rota POST/PUT/PATCH/DELETE sem decorator de autenticação/autorização nem checagem no corpo, ou rota `/admin` sem checagem de papel (`@login_required` basta para rota comum, não basta para `/admin`). Rotas públicas por natureza (login, cadastro, webhook) são ignoradas; `before_request` no arquivo suprime todas.
- **Principais classes/funções**: `DetectorAutorizacao`, `PREFIXO_CANDIDATO`, `_e_rota_publica()`, `_e_administrativa()`, `_checagens_no_corpo()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/estrutura`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_csrf_autorizacao.py`.

#### `detectores/autenticacao.py` (606 linhas — maior detector)

- **Função**: seis detectores de falhas de autenticação/proteção de credenciais.
- **Responsabilidade**: `DetectorJwtSemVerificacao` (CWE-287, `verify=False`/`options={"verify_signature": False}`), `DetectorHashDeSenhaFraco` (CWE-916, md5/sha1 sobre senha), `DetectorSenhaEmTextoPuro` (CWE-256, taint: senha da requisição sem hash até persistência/comparação), `DetectorCookieInseguro` (CWE-614/1004, `set_cookie` sem `secure`/`httponly`), `DetectorExpiracaoDeSessao` (CWE-613, `PERMANENT_SESSION_LIFETIME` longo), `DetectorLoginSemLimite` (CWE-307, candidato: POST /login sem `@limiter.limit`/contagem de tentativas).
- **Principais classes/funções**: as 6 classes acima + helpers `menciona_senha()`, `_nomeia_senha()`, `avaliar_duracao()`, `_resolver()`, `_achado()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/confianca`, `motor/estrutura`, `motor/taint`.
- **Dependentes**: `varredura.py`, `tests/test_autenticacao.py` (32 testes).

#### `detectores/credenciais.py` (328 linhas)

- **Função**: credenciais fixas (CWE-798) em dois contextos.
- **Responsabilidade**: `DetectorCredenciais` (AST Python: atribuições, kwargs, chaves de dict, defaults de parâmetro, fallback de `os.getenv`, `auth=(u,p)`, `smtp.login`, `create_superuser`, comparação com literal, URL com senha embutida) e `DetectorCredenciaisEmConfiguracao` (recebe `ArquivoDeConfiguracao` pronto da varredura — único detector fora do fluxo arquivo+escopos). Segredos sempre mascarados via `motor/credenciais.mascarar`.
- **Principais classes/funções**: `DetectorCredenciais`, `DetectorCredenciaisEmConfiguracao`, `_texto()`.
- **Depende de**: `achado`, `analisador`, `motor/catalogo`, `motor/credenciais`, `motor/estrutura`; stdlib `urllib.parse`.
- **Dependentes**: `varredura.py`, `tests/test_credenciais.py`, `tests/test_configuracao.py`.

### Núcleo — orquestração, saída e entradas

#### `TOOL/owaspscan/varredura.py` (130 linhas)

- **Função**: orquestração ponta-a-ponta — o mapa do sistema.
- **Responsabilidade**: `executar(raiz)` analisa diretório/arquivo, roda taint + 15 detectores por arquivo Python, lê configurações e roda o detector de credenciais nelas, agregando em `Varredura` (achados ordenados, contadores, falhas, momento, versão). I/O mora aqui; formatação mora em `relatorio.py`.
- **Principais classes/funções**: `VERSAO` ("0.2.0"), `CONFIANCA_DE_CANDIDATO`, `detectores_padrao()`, `Varredura` (`confirmados`, `candidatos`, `tem_severidade_alta`), `executar()`.
- **Dependências**: stdlib (`dataclasses`, `datetime`, `pathlib`).
- **Depende de**: `achado`, `analisador`, `configuracao`, `motor/catalogo`, `motor/taint` e **todos os 11 módulos de detectores** — é o único arquivo que conhece tudo.
- **Dependentes**: `cli.py`, `api.py`, `relatorio.py`, `metricas.py`, `tests/` (integracao, metricas, configuracao).

#### `TOOL/owaspscan/relatorio.py` (213 linhas)

- **Função**: resumo executivo — módulo **puro** (sem disco, sem detectores).
- **Responsabilidade**: `formatar_texto()` monta o relatório de terminal (contagens agregadas, seções separadas "ACHADOS RASTREADOS POR TAINT" / "CANDIDATOS HEURISTICOS", recomendações por CWE, arquivos não analisados); `para_dict()` produz o JSON com metadados de execução (rastreabilidade das métricas). O corte de seções é `confianca == "baixa"`, não a CWE.
- **Principais classes/funções**: `Resumo`, `resumir()`, `ordenar()`, `formatar_texto()`, `para_dict()`, `LARGURA`.
- **Depende de**: `achado.py`, `varredura.py` (reexporta `Varredura`).
- **Dependentes**: `cli.py`, `api.py`, `tests/test_relatorio.py`.

#### `TOOL/owaspscan/cli.py` (75 linhas) + `__main__.py` (5 linhas)

- **Função**: interface de linha de comando (`python -m owaspscan caminho [--json]`).
- **Responsabilidade**: parsear argv, validar caminho, executar varredura, imprimir relatório (com `--json`: JSON no stdout, resumo no stderr — encadeável com `jq`) e devolver exit code: `0` sem achado alto, `1` com achado alto, `2` erro de uso. Candidatos heurísticos não alteram o exit code (decisão documentada).
- **Principais funções/constantes**: `montar_parser()`, `main()`, `CODIGO_OK`/`CODIGO_ACHADO_ALTO`/`CODIGO_ERRO_DE_USO`.
- **Depende de**: `relatorio.py`, `varredura.py`; stdlib (`argparse`, `json`, `sys`, `pathlib`).
- **Dependentes**: `__main__.py`, `tests/test_integracao.py` (20 testes ponta-a-ponta).

#### `TOOL/owaspscan/api.py` (229 linhas)

- **Função**: camada HTTP para o site — dependência opcional (extra `[api]`); o núcleo segue stdlib-only.
- **Responsabilidade**: `POST /analisar` aceita JSON **ou** multipart/form-data e devolve exatamente o JSON do `--json` com `raiz="envio"`; `GET /saude`; OpenAPI em `/docs`. Valida entrada hostil: nome reduzido ao nome-base (sem path traversal), só `.py`/configuração, ≤50 arquivos, ≤1 MB cada, sem duplicatas (erros 400/413/415/422). Grava em `TemporaryDirectory`, analisa, destrói a pasta. Varredura roda em `run_in_threadpool` (CPU-bound fora do event loop). CORS configurável.
- **Principais classes/funções**: `app` (FastAPI), `ArquivoEnviado`/`Envio` (pydantic), `nome_seguro()`, `montar_envios()`, `varrer()`, `analisar()`, `saude()`, `main()`; constantes `MAXIMO_DE_ARQUIVOS`, `TAMANHO_MAXIMO_POR_ARQUIVO`, `ORIGENS`.
- **Dependências externas**: fastapi, pydantic, starlette, uvicorn, python-multipart.
- **Depende de**: `configuracao.py` (`formato_de`), `relatorio.py` (`para_dict`), `varredura.py` (`executar`, `VERSAO`).
- **Variáveis de ambiente**: `OWASPSCAN_HOST` (127.0.0.1), `OWASPSCAN_PORTA` (8000), `OWASPSCAN_ORIGENS` (`*`).
- **Dependentes**: `tests/test_api.py` (26 testes, via httpx/TestClient); futuro consumo pelo frontend (ainda não implementado).

#### `TOOL/owaspscan/configuracao.py` (260 linhas)

- **Função**: leitura de arquivos de configuração não-Python (exceção declarada ao princípio "somente AST").
- **Responsabilidade**: descobrir e parsear `.env`, `.properties`, INI/CFG/CONF, TOML (linha a linha `chave = valor`), JSON (parser stdlib completo) e YAML (pares `chave: valor` + itens `- CHAVE=valor`; sem blocos/multi-linha/âncoras) para busca de credenciais. Teto de 1 MB; falhas viram `FalhaDeLeitura`.
- **Principais classes/funções**: `EntradaDeConfiguracao`, `ArquivoDeConfiguracao`, `formato_de()`, `descobrir_configuracoes()`, `ler_linhas_chave_valor()`, `ler_yaml()`, `ler_json()`, `ler_configuracao()`, `ler_diretorio()`.
- **Depende de**: `analisador.py`; stdlib (`json`, `dataclasses`, `pathlib`).
- **Dependentes**: `varredura.py`, `api.py`, `metricas.py`, `tests/test_configuracao.py`.

#### `TOOL/owaspscan/metricas.py` (184 linhas)

- **Função**: autoavaliação da ferramenta contra corpus rotulado (`python -m owaspscan.metricas caminho`).
- **Responsabilidade**: carregar o gabarito embutido nas amostras (comentário na linha do sink: `# achado: CWE-x` / `# limitacao: CWE-x`), rodar `executar()`, confrontar achados × gabarito (VP/FP/FN) e calcular precisão/recall/F1 por CWE. **Limitação declarada conta como falso negativo.**
- **Principais classes/funções**: `ItemDeGabarito`, `carregar_gabarito()`, `Metricas`, `avaliar()`, `formatar_tabela()`, `main()`.
- **Depende de**: `achado.py` (MAPA), `configuracao.py`, `varredura.py`; stdlib (`re`, `sys`, `dataclasses`, `pathlib`). É o único módulo do núcleo que usa `re` — apenas para ler comentários de gabarito, não código.
- **Dependentes**: `tests/conftest.py`, `tests/test_metricas.py`, `tests/test_integracao.py`.

#### `TOOL/pyproject.toml`

- **Função**: definição do pacote `owaspscan` 0.2.0 (Python ≥3.11).
- **Conteúdo relevante**: `dependencies = []` (núcleo stdlib-only); extras `api` (fastapi, uvicorn, python-multipart) e `dev` (pytest, httpx); build via setuptools; `[tool.pytest.ini_options]` (`testpaths = ["tests"]`, `-q`).
- **Dependentes**: pip, pytest, qualquer tooling.

### Testes (`TOOL/tests/`)

#### `tests/conftest.py` (48 linhas)

- **Função**: apoio compartilhado — leitura do gabarito e atalhos para rodar detectores.
- **Principais funções**: `linhas_esperadas()`, `linhas_de_limitacao()`, `rodar_detector()` (código em memória), `rodar_detector_em_arquivo()` (amostra do corpus).
- **Depende de**: `metricas.py`, `analisador.py`, `motor/taint.py`.

#### Arquivos de teste (19, ~336 testes)

| Arquivo | Cobre | Testes |
| --- | --- | --- |
| `test_contrato.py` | `achado.py` — mapa CWE→OWASP fechado | 13 |
| `test_analisador.py` | descoberta, parse resiliente, localização | 18 |
| `test_taint.py` | motor de taint (ponto fixo, escopos, propagação) | 38 |
| `test_sanitizacao.py` | sanitizadores por CWE | 13 |
| `test_estrutura.py` | consultas estruturais | 15 |
| `test_sqli.py` · `test_xss.py` · `test_idor.py` · `test_xxe.py` · `test_path_traversal.py` · `test_open_redirect.py` · `test_csrf_autorizacao.py` · `test_autenticacao.py` · `test_credenciais.py` | cada detector contra amostras e código em memória | 15·22·22·14·11·8·17·32·15 |
| `test_configuracao.py` | parsers de configuração + detector nelas | 17 |
| `test_relatorio.py` | formatação texto/JSON | 21 |
| `test_api.py` | endpoints, validações, limites, erros | 26 |
| `test_integracao.py` | CLI ponta-a-ponta + exit codes | 20 |
| `test_metricas.py` | gabarito e cálculo de métricas | 19 |

#### `tests/amostras/` (corpus, dupla função: fixtures + avaliação)

| Pasta | Conteúdo |
| --- | --- |
| `vulneravel/` | 11 `.py` + `config/` (5 arquivos) com vulnerabilidades reais marcadas `# achado: CWE-x`; inclui 1 erro de sintaxe proposital |
| `seguro/` | contrapartes seguras **para a CWE que nomeiam** (não para todas) + `config/` |
| `analisador/` | `modulo_exemplo.py`, `quebrado.py` (parse resiliente) |

### Frontend (`frontend/`)

#### `frontend/src/App.jsx` (382 linhas)

- **Função**: aplicação inteira em arquivo único.
- **Responsabilidade**: estado de navegação (`paginaAtual`), tema dark/light persistido em `localStorage` (`aegis-tema`), i18n pt/en, abas de análise (file/url/snippet/cli), drag & drop (arquivos ficam só no `useState` — **nenhum envio**), páginas estáticas com texto hardcoded (docs oficial, termos, privacidade, como usar, FAQ, scripts).
- **Componentes**: `SunIcon`, `MoonIcon`, `TerminalIcon`, `DownloadIcon`, `FileCheckIcon`, `AIcon`, `App`.
- **Depende de**: `react`, `./translate`.
- **Dependentes**: `main.jsx`.
- ⚠️ Os textos exibidos descrevem funcionalidades inexistentes (malware/URLs/domínios, JS/PHP/C++, `@aegis/cli`, `api.aegis.dev`) — ver `docs/arquitetura.md`, seção de riscos.

#### `frontend/src/translate.js` (59 linhas)

- **Função**: dicionário de traduções `traducoes = { pt: {...}, en: {...} }`.
- **Dependentes**: `App.jsx`.

#### `frontend/src/main.jsx` (10 linhas)

- **Função**: bootstrap — `createRoot(#root).render(<StrictMode><App/></StrictMode>)` + `index.css`.

#### `frontend/package.json` · `vite.config.js` · `tailwind.config.js` · `postcss.config.js` · `.oxlintrc.json` · `index.html`

- **Função**: build e qualidade — scripts `dev`/`build`/`lint`(oxlint)/`preview`; React 19 + `@vitejs/plugin-react` (Vite 8); Tailwind com dark mode por classe; `index.html` é o shell (favicon SVG inline, `#root`). Sem proxy/env configurado para a API do TOOL.

### Raiz e gestão

| Arquivo | Função | Estado |
| --- | --- | --- |
| `README.md` | identificação institucional, problema, solução proposta, links | preenche problema/solução; backlog "vincular" pendente; cita pre-commit/CI ainda inexistentes |
| `TOOL/README.md` | **documentação técnica principal**: tabela de cobertura (16 CWEs), uso, API HTTP, limitações do motor, calibração de confiança, avaliação, estado das fases | completo e denso; "Estado" lista até Fase 16 (git mostra Fase 19) |
| `TOOL/CLAUDE.md` | princípios de desenvolvimento (AST nunca regex, contrato do achado, mapa CWE→OWASP fixo, IDOR heurístico, fases pequenas com teste+commit) | referência obrigatória para contribuir |
| `docs/arquitetura.md` | arquitetura real do sistema | ✅ preenchido (etapa 02) |
| `docs/estrutura.md` | este inventário | ✅ |
| `docs/requisitos.md` | requisitos do produto | template genérico, não preenchido |
| `docs/decisoes/` · `docs/reunioes/` | ADRs e atas | apenas README + template |
| `SECURITY.md` | política de segredos/incidentes | preenchido (genérico institucional) |
| `CHANGELOG.md` | histórico | parado na Sprint 00 |
| `CONTRIBUTING.md` · `CODE_OF_CONDUCT.md` · `LICENSE` | contribuição, conduta, licença | templates; LICENSE é placeholder sem licença efetiva |
| `sprints/sprint-00-planejamento.md` | registro da sprint inicial | template não preenchido |
| `entregas/fontes/equipe` | contatos da equipe | ⚠️ contém e-mails institucionais no repositório |
| `.github/ISSUE_TEMPLATE/*.yml` · `PULL_REQUEST_TEMPLATE.md` | padronização de issues/PRs | ativos; sem workflows (não há CI/CD) |
| `Artigo_Vulnerabilidades_Codigo_IA.pdf` | artigo acadêmico de base (motivação do problema) | referência |

## Grafo de dependências (imports internos verificados)

```
achado.py ◄─────────────── todos os detectores · relatorio · metricas · tests
analisador.py ◄─────────── taint · base · configuracao · varredura · tests
catalogo.py ◄───────────── taint · estrutura · confianca · comum · 9 detectores
taint.py ──► analisador · catalogo ◄── varredura · base · comum · confianca · detectores · tests
estrutura.py ──► catalogo ◄── credenciais(motor) · comum · 7 detectores · tests
credenciais.py (motor) ──► estrutura ◄── detectores/credenciais · detectores/autenticacao
confianca.py ──► catalogo · taint ◄── 6 detectores de taint · autenticacao
configuracao.py ──► analisador ◄── varredura · api · metricas · tests
varredura.py ──► tudo acima + 11 detectores ◄── cli · api · relatorio · metricas · tests
relatorio.py ──► achado · varredura ◄── cli · api · tests
cli.py ──► relatorio · varredura ◄── __main__ · tests
api.py ──► varredura · relatorio · configuracao (+ fastapi/uvicorn/pydantic) ◄── tests
metricas.py ──► achado · configuracao · varredura ◄── conftest · tests
```

Regras estruturais observadas no código: dependências são unidirecionais (não há ciclos); `varredura.py` é o único ponto que conhece todos os detectores; detectores nunca importam `varredura`/`relatorio`/`cli`/`api`; `achado.py` e `catalogo.py` não importam nada do pacote.

## Trilha de leitura recomendada

**Para entender o produto (1–2 h):**
`TOOL/CLAUDE.md` → `TOOL/README.md` → `docs/arquitetura.md` → `achado.py` → `varredura.py` → `cli.py`.

**Para contribuir com um detector novo:**
`achado.py` (contrato) → `detectores/base.py` (Protocol) → `detectores/sqli.py` (padrão taint mínimo, 79 linhas) → `motor/catalogo.py` (onde declarar fonte/sink/sanitizador) → `motor/taint.py` (`Escopo`/`Procedencia`) → `detectores/idor.py` (padrão heurístico, se for candidato) → `tests/test_sqli.py` + `tests/amostras/` (como testar e rotular) → `varredura.py` (registrar em `detectores_padrao`).

**Para trabalhar na API/integração web:**
`TOOL/README.md` §"API HTTP (para o site)" → `api.py` → `tests/test_api.py` → `frontend/src/App.jsx` (UI a integrar).

**Para trabalhar no frontend:**
`frontend/src/main.jsx` → `App.jsx` → `translate.js` → `tailwind.config.js`/`package.json`.

**Para avaliação/qualidade:**
`metricas.py` → `tests/amostras/` (gabarito embutido) → `TOOL/README.md` §"Avaliação" e §"Limitações declaradas".

## Exclusões

Não fichados por serem gerados, binários, de terceiros ou sem conteúdo: `node_modules/`, `package-lock.json`, `.git/`, `__pycache__/`, `*.egg-info/`, `.venv/`, `.pytest_cache/`, `frontend/src/assets/*` (imagens), `frontend/public/*` (SVGs estáticos), `frontend/src/App.css` (vazio), `frontend/src/index.css` (2 linhas: diretivas Tailwind), `sprints/template-sprint.md`, `entregas/template-entrega.md`, `docs/decisoes/template-adr.md`, `docs/reunioes/template-reuniao.md` (templates institucionais em branco), READMEs de `sprints/`, `entregas/`, `docs/decisoes/`, `docs/reunioes/` (texto padrão de orientação).
