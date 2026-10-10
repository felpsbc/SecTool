# Segurança

Análise da arquitetura de segurança do projeto AEGIS — documentação e compreensão da implementação existente, sem exploração ofensiva. Tudo foi confirmado no código; os achados estão classificados em **IMPLEMENTADO**, **PARCIALMENTE IMPLEMENTADO** e **NÃO IDENTIFICADO**.

## Escopo e contexto

O projeto tem duas dimensões de segurança que não devem ser confundidas:

1. **Segurança DO sistema** (objeto deste documento): como CLI, API HTTP e frontend se protegem e protegem os dados dos usuários.
2. **Segurança como produto**: o motor `owaspscan` *detecta* 16 CWEs em código de terceiros (SQLi, XSS, IDOR, XXE, credenciais fixas etc. — ver `TOOL/README.md` §Cobertura). Isso é lógica de negócio, não mecanismo de proteção do próprio projeto, e não é reavaliado aqui.

Superfície real do sistema: **CLI local** (lê disco do usuário, imprime no terminal), **API HTTP** (`TOOL/owaspscan/api.py`, FastAPI/Uvicorn, localhost por padrão) e **frontend estático** (protótipo React sem chamadas de rede). Não há banco de dados, contas de usuário, serviços externos nem comunicação de saída (ver `docs/banco-de-dados.md` e `docs/api.md`).

## Resumo por dimensão

| Dimensão | Estado | Onde |
| --- | --- | --- |
| Validação de entrada (API) | ✅ IMPLEMENTADO | `api.py:75-120` |
| Uploads seguros | ✅ IMPLEMENTADO | `api.py:123-130` |
| Não-execução de código hostil | ✅ IMPLEMENTADO | todo o núcleo (AST only) |
| Exposição de informações | ✅ IMPLEMENTADO | `api.py:43,130,137`; `motor/credenciais.py:246` |
| Secrets no repositório | ✅ IMPLEMENTADO (política + .gitignore) | `SECURITY.md`, `.gitignore` |
| Cadeia de suprimentos (dependências) | ✅ IMPLEMENTADO (minimalismo) | `pyproject.toml` |
| XSS no frontend | ✅ IMPLEMENTADO (por construção React) | `frontend/src/` |
| CORS | ⚠️ PARCIAL | `api.py:46,67-72` |
| Binding de rede | ⚠️ PARCIAL | `api.py:223` |
| Limite de tamanho do corpo JSON | ⚠️ PARCIAL | `api.py:133-141` |
| Rate limiting / abuso de CPU | ⚠️ NÃO IMPLEMENTADO | — |
| Autenticação | ❌ NÃO IDENTIFICADO | — |
| Autorização / permissões | ❌ NÃO IDENTIFICADO | — |
| Sessão / cookies / tokens | ❌ NÃO IDENTIFICADO (não se aplica) | — |
| Senhas (do sistema) | ❌ NÃO IDENTIFICADO (não existem) | — |
| SQL/NoSQL queries | ❌ NÃO IDENTIFICADO (não existem) | — |
| CSRF (proteção da API) | ❌ NÃO IDENTIFICADO (não se aplica) | — |
| Criptografia (TLS, em repouso) | ❌ NÃO IDENTIFICADO | — |
| Logs / auditoria / monitoramento | ❌ NÃO IDENTIFICADO (só `/saude`) | — |
| Comunicação externa (saída) | ❌ NÃO IDENTIFICADO (não existe) | — |

---

## IMPLEMENTADO

### 1. Validação de entrada da API em camadas

Toda requisição `POST /analisar` passa por validações antes de qualquer análise (`api.py`):

| Camada | Mecanismo | Onde |
| --- | --- | --- |
| Content-Type | dispatch explícito: só `application/json`, `multipart/form-data` ou `x-www-form-urlencoded`; demais → 415 | `api.py:192-198` |
| Esquema (JSON) | modelos pydantic `Envio`/`ArquivoEnviado`; violação → 422 | `api.py:49-59,133-141` |
| Parser multipart | tetos Starlette `max_files=51`, `max_part_size=2MB` como rede de proteção | `api.py:147-149` |
| Quantidade | ≤ 50 arquivos por envio → 413 | `api.py:102-103` |
| Tamanho | ≤ 1.000.000 bytes por arquivo; multipart lê 1 byte além do teto para detectar excesso sem baixar o arquivo inteiro → 413 | `api.py:113-116,156` |
| Nome de arquivo | `nome_seguro()`: reduz ao **nome-base** descartando qualquer diretório POSIX ou Windows (`../../etc/app.py` → `app.py`; `C:\projeto\models.py` → `models.py`); rejeita vazio/`.`/`..`; exige extensão `.py` ou de configuração reconhecida → 400 | `api.py:75-91` |
| Duplicatas | nomes repetidos (após redução) → 400 | `api.py:111-112` |
| Vazio | envio sem conteúdo efetivo → 400 | `api.py:118-119` |

Comportamentos confirmados por testes, inclusive de entrada hostil: `TOOL/tests/test_api.py` (classes `TestEntradaHostil`, `TestCorpoJson`).

### 2. Uploads: armazenamento efêmero e isolamento

- Arquivos gravados em `tempfile.TemporaryDirectory(prefix="owaspscan-")` **por requisição** e destruídos automaticamente na saída do bloco `with` — antes de a resposta ser montada (`api.py:123-130`). Nada persiste em disco.
- Como os nomes são reduzidos ao nome-base, é impossível gravar fora da pasta temporária (path traversal neutralizado na camada de nome, testado em `test_api.py:101-107`).
- O caminho real da pasta nunca volta ao cliente: a resposta reescreve `raiz` para `"envio"` (`api.py:43,130`; `test_api.py:53-56` verifica que nem o prefixo `owaspscan-` aparece).

### 3. Código enviado nunca é executado

Garantia arquitetural central: o motor só faz `ast.parse` — nunca `exec`, `eval`, `import` dinâmico ou subprocesso do código analisado (varredura confirmou zero ocorrências de `eval(`/`exec(` em `TOOL/owaspscan/`). Documentado em `api.py:15-17` ("O codigo do usuario nunca e executado: o motor so parseia a AST. Mesmo assim a entrada e hostil por definicao") e nos termos exibidos pelo frontend. Consequências:

- Arquivo com sintaxe inválida não derruba o processo: vira `FalhaDeLeitura` na resposta 200 (`analisador.py:112-151`).
- Falha de codificação ou byte nulo também são tratadas como dado (`analisador.py:120-147`).

### 4. Controle de exposição de informações

- **Segredos mascarados**: credenciais detectadas (CWE-798) têm o valor mascarado no trecho do relatório — princípio declarado: "a ferramenta não pode ser o vazamento que denuncia" (`motor/credenciais.py:246`, `TOOL/README.md` §Credenciais fixas).
- **Erros pydantic sem URLs internas**: `erro.errors(include_url=False)` evita vazar detalhes de versão/caminhos do framework (`api.py:137`).
- **Sem vazamento de caminhos do servidor** (item 2).
- Mensagens de erro revelam apenas o nome/limites do próprio envio.

### 5. Política e higiene de secrets no repositório

- `SECURITY.md`: proibição de credenciais no repositório, uso de variáveis de ambiente, procedimento de incidente (avisar, remover, **rotacionar** — "considere comprometida mesmo após remoção").
- `.gitignore` (raiz): `.env`, `.env.*` (com exceção só para `!.env.example`), `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.local`.
- Os segredos que existem no repositório são **fictícios**, em fixtures de teste (`TOOL/tests/amostras/*/config/`) — corpus do detector de credenciais.
- O código-fonte do projeto não contém nenhuma credencial (única leitura de env vars: as 3 variáveis de rede da API).
- ⚠️ Exceção a registrar: `entregas/fontes/equipe` contém e-mails institucionais reais da equipe (dado pessoal, não segredo — inconsistência já apontada em `docs/arquitetura.md`).

### 6. Cadeia de suprimentos minimalista

- Núcleo: `dependencies = []` (`pyproject.toml:6`) — **zero** pacotes de terceiros no scanner; superfície de vulnerabilidade de dependências praticamente nula e funcionamento 100% offline.
- FastAPI/Uvicorn isolados como extra `[api]` — decisão explícita (`api.py:19-21`): quem só usa a CLI não instala framework web.
- Frontend: 2 dependências de runtime (react, react-dom); o resto é dev-only; `package-lock.json` congela resoluções.
- Ironia produtiva: o projeto existe justamente porque dependências geradas por IA/código de terceiros são arriscadas — e aplica a si mesmo o princípio de mínima confiança em dependências.

### 7. XSS no frontend: seguro por construção

- React com JSX: saída de texto é auto-escapada; **nenhum** `dangerouslySetInnerHTML`, `innerHTML` ou `eval` em `frontend/src/` (verificado por varredura).
- Páginas estáticas (termos, FAQ etc.) são strings em `conteudosPagina` renderizadas como texto (`App.jsx:305-312`) — o "markdown" interno não é parseado como HTML.
- ⚠️ Ressalva de conteúdo, não de mecanismo: os textos exibidos descrevem serviços inexistentes (`api.aegis.dev`, `Bearer SEU_TOKEN` de exemplo) — risco de confusão do usuário, registrado em `docs/arquitetura.md`.

### 8. Gate de segurança para automação (CLI)

Exit codes projetados para CI/pre-commit: `1` quando há achado de severidade alta (`cli.py:24-26,71`). Decisão de segurança deliberada: candidatos heurísticos (confiança baixa) **não** quebram builds — evita dessensibilização por falso positivo (`cli.py:10-11`, `TOOL/README.md` §Uso).

---

## PARCIALMENTE IMPLEMENTADO

### 1. CORS — existe, mas padrão aberto

`CORSMiddleware` configurado (`api.py:67-72`): `allow_origins` vem de `OWASPSCAN_ORIGENS` (vírgula-separado), `allow_methods` fixo `["GET","POST"]`, `allow_headers` `["*"]`, `allow_credentials` não habilitado. **Porém o padrão é `*`** (`api.py:46`): sem configuração, qualquer origem é aceita. Para um serviço localhost sem autenticação e sem dados de usuário, o impacto é limitado; se a API for exposta em rede, `*` permite que qualquer site a utilize. Mitigação documentada em `docs/configuracao.md` §1 (restringir origens fora de dev).

### 2. Binding de rede — seguro por padrão, perigoso por opção

Padrão `127.0.0.1` (`api.py:223`) mantém a API fora da rede. Mas `OWASPSCAN_HOST=0.0.0.0` é aceito sem nenhum aviso — e como **não há autenticação** (abaixo), expor a API é expor um analisador de código aberto a quem alcançá-la. Não há validação nem alerta no código contra essa combinação.

### 3. Limite de tamanho — completo no multipart, tardio no JSON

No multipart os tetos do Starlette limitam o que é lido do socket (`api.py:147-149,156`). No JSON, `await request.json()` carrega o **corpo inteiro em memória** (`api.py:135`) antes de `montar_envios()` aplicar o limite de 1 MB por arquivo — um corpo JSON arbitrariamente grande é alocado antes da rejeição (registrado em `docs/api.md` §Limitações). Também não há limite de tamanho total do envio (só por arquivo), nem `Content-Length` máximo no nível ASGI.

### 4. Disponibilidade / abuso de recurso — proteções parciais

Existe: análise roda em threadpool (`run_in_threadpool`, `api.py:200`), então o event loop não é bloqueado; tetos de tamanho/quantidade limitam o pior caso por requisição. Não existe: rate limiting, timeout de análise (o ponto fixo do taint roda até convergir), limite de concorrência, fila — requisições simultâneas ilimitadas competem por CPU. Aceitável para localhost; insuficiente para qualquer exposição pública.

### 5. Privacidade do frontend — coerente com o backend, mas não implementada no frontend

O texto de privacidade exibido ("processados de forma efémera na memória... não armazenamos o código") descreve corretamente o comportamento real da API (`api.py:123-130`). Porém, como o frontend ainda não envia nada (não há `fetch`), hoje a garantia vale apenas para quem chama a API diretamente. Trechos do mesmo texto prometem o que não existe ("colaborar com a comunidade enviando hashes", "histórico para usuários autenticados") — desalinhamento conteúdo × implementação.

---

## NÃO IDENTIFICADO

Ausências verificadas por varredura do código. Várias são "não se aplica" legítimos para o escopo atual (ferramenta local, sem usuários); estão listadas para deixar a superfície explícita.

| Dimensão | Situação | Evidência / observação |
| --- | --- | --- |
| **Autenticação** | Inexistente. Nenhum endpoint verifica identidade (sem API key, bearer, basic auth, sessão). | `api.py` inteiro: nenhum mecanismo; `test_api.py` chama tudo sem credenciais. Consequência: a segurança do deployment depende 100% de manter o bind em localhost ou de um proxy externo |
| **Autorização / permissões** | Inexistente — sem identidade, não há papéis/permissões. | idem |
| **Gerenciamento de sessão** | Não existe. API stateless por design; nenhuma sessão criada ou lida. | nenhuma biblioteca de sessão instalada (`pyproject.toml`) |
| **Senhas do sistema** | Não existem (não há usuários). O projeto apenas *detecta* senhas fracas/hardcoded em código de terceiros (CWE-916/256/798). | `detectores/autenticacao.py`, `detectores/credenciais.py` |
| **Tokens** | Nenhum token emitido ou validado pela aplicação. (`Bearer SEU_TOKEN` aparece só em texto ilustrativo do frontend.) JWT é tema de detector (CWE-287), não mecanismo próprio. | `App.jsx:292`; `detectores/autenticacao.py:119` |
| **Cookies** | A aplicação não define nem lê cookies (nem de sessão). Cookies inseguros são tema de detector (CWE-614/1004). Frontend usa apenas `localStorage` (tema). | `api.py` (sem `set_cookie`); `App.jsx:33,61` |
| **SQL / NoSQL queries** | O sistema não executa nenhuma query — não há banco. Strings SQL no repositório são sinks do catálogo e fixtures de teste, nunca executadas. | `docs/banco-de-dados.md` |
| **Proteção CSRF (da API)** | Não existe token CSRF. Na prática **não se aplica**: sem autenticação, sem cookies e sem estado, não há ação privilegiada a forjar; CORS restringe leituras cross-origin por navegador. Se autenticação for adicionada no futuro, CSRF precisará ser reavaliado (a API aceita `x-www-form-urlencoded`, que é "simple request" navegável). | `api.py:67-72,195` |
| **Criptografia** | Nenhuma: HTTP puro (sem TLS — Uvicorn sem certificado), nada criptografado em repouso (nada é armazenado). Para localhost é aceitável; para rede exigiria proxy TLS. Hash aparece só como tema de detector. | `api.py:218-225` |
| **Logs e auditoria** | Nenhum log de aplicação (sem registro de requisições, achados, erros ou acessos além do logging padrão do Uvicorn no console). `/saude` é o único endpoint de monitoramento. Não há trilha de auditoria — coerente com a promessa de não reter código enviado, mas inviabiliza detecção de abuso se exposto. | `api.py:164-166`; ausência de `logging` em `owaspscan/` |
| **Comunicação externa (saída)** | Inexistente: o processo nunca faz chamadas de rede para fora (nem telemetry, nem updates). Só recebe. Reduz drasticamente exfiltração possível. | nenhum client HTTP em `owaspscan/`; httpx apenas em `dev` (testes) |
| **Sanitização de saída** | Não se aplica no sentido clássico: as saídas são texto plano no terminal e JSON. O único cuidado necessário — mascarar segredos — está implementado (ver acima). HTML não é gerado pelo backend. | `relatorio.py`; `motor/credenciais.py:246` |
| **Gestão de vulnerabilidades das dependências** | Sem dependabot, sem `pip-audit`/`npm audit` automatizado, sem CI (`.github/workflows/` inexistente). Lockfile npm existe e ajuda; no lado Python os extras têm pisos de versão (`fastapi>=0.110` etc.), não tetos. | `.github/`, `pyproject.toml` |

---

## Modelo de ameaça simplificado (o que a implementação atual pressupõe)

O desenho de segurança do projeto é coerente com um **modelo de confiança explícito**:

1. **A entrada é hostil, o ambiente é confiável.** Todo o esforço de validação está na fronteira de entrada da API (nomes, tamanhos, tipos, conteúdo nunca executado). Em compensação, não há defesa contra quem alcança a própria API — o pressuposto é que ela só escuta em localhost para o dono da máquina.
2. **O usuário do código analisado é a vítima protegida.** Código enviado não é executado, não é retido, não tem caminho vazado e tem segredos mascarados — proteções para quem submete código à ferramenta.
3. **Nenhum dado vale persistir.** A ausência de banco/estado elimina classes inteiras (injeção em banco próprio, roubo de sessão, vazamento em repouso).

Riscos residuais decorrentes do modelo (registrados, não explorados): expor a API em rede sem proxy (sem auth + CORS `*` + sem rate limit); corpo JSON gigante antes da validação de tamanho; ausência de logs impede detectar abuso; e-mail da equipe commitado em `entregas/fontes/equipe`.

## Recomendações (não implementadas — apenas documentação)

Priorizadas para o cenário de vir a expor a API além de localhost:

1. Autenticação mínima (API key por header) antes de qualquer bind não-local; 2. `OWASPSCAN_ORIGENS` restrito por ambiente (nunca `*` fora de dev); 3. rate limiting e timeout de análise; 4. limite de tamanho de corpo antes do parse JSON (checar `Content-Length`); 5. warning no log ao subir com host != 127.0.0.1 sem autenticação; 6. logging estruturado de requisições (sem conteúdo do código, para preservar a promessa de privacidade); 7. TLS via reverse proxy em produção; 8. CI com pytest + auditoria de dependências (`pip-audit`, `npm audit`); 9. remover e-mails pessoais de `entregas/fontes/equipe`; 10. alinhar textos do frontend às funcionalidades reais.

## Referências

- Implementação: `TOOL/owaspscan/api.py` (fronteira HTTP), `analisador.py` (resiliência), `motor/credenciais.py` (mascaramento), `relatorio.py` (saídas), `cli.py` (exit codes)
- Testes que confirmam comportamentos: `TOOL/tests/test_api.py` (entrada hostil, CORS, não vazamento), `test_contrato.py`
- Políticas: `SECURITY.md`, `.gitignore` (raiz)
- Documentos relacionados: `docs/api.md` (contrato e limitações), `docs/configuracao.md` (env vars e impacto), `docs/banco-de-dados.md` (ausência de persistência), `docs/arquitetura.md` §Segurança da própria ferramenta
- Cobertura de detecção (produto): `TOOL/README.md` §Cobertura e §Limitações declaradas
