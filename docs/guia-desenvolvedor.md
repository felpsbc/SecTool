# Guia do desenvolvedor

Onboarding para quem acabou de entrar na equipe e nunca viu este projeto. Responde, na prática, onde tudo fica e por onde começar. Leitura complementar: `docs/arquitetura.md` (visão completa), `docs/estrutura.md` (inventário arquivo a arquivo), `docs/instalacao.md` (setup detalhado).

## 1. O que é este projeto?

**AEGIS** é um projeto acadêmico do CEUB (ID 20260229) que entrega uma ferramenta de análise estática de segurança (SAST) chamada **OWASP-Scan**: ela lê código Python (Django/Flask) e arquivos de configuração e aponta vulnerabilidades do OWASP Top 10:2021 — sem executar o código analisado, só parseando a árvore sintática (AST).

O repositório tem 3 partes:

| Parte | Onde | Estado |
| --- | --- | --- |
| Motor SAST (núcleo + CLI + API) | `TOOL/` | maduro, ~336 testes, 19 fases commitadas |
| Frontend web | `frontend/` | protótipo visual — **ainda não chama a API** |
| Documentação/gestão da disciplina | `docs/`, `sprints/`, `entregas/`, `.github/` | parcialmente preenchida |

## 2. O que ele faz?

Recebe código-fonte (diretório via CLI ou upload via API HTTP), rastreia dados não confiáveis de **fontes** (`request.args`, parâmetros de rota...) até **sinks** perigosos (`cursor.execute`, `redirect`...) verificando **sanitização** no caminho (taint tracking), além de checagens estruturais (cookies, JWT, CSRF, credenciais fixas...). Devolve um relatório com achados classificados por CWE/OWASP, severidade (alta/média/baixa) e confiança — cada achado traz explicação educativa e recomendação de correção. Cobre 16 CWEs (tabela em `TOOL/README.md` §Cobertura).

## 3. Como executar localmente?

Resumo (detalhes e solução de problemas: `docs/instalacao.md`). Pré-requisitos: **Python ≥3.11** e (para o frontend) **Node 20.19+/22.12+**.

```bash
# Motor + CLI
cd TOOL
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"          # testes
.venv/bin/python -m owaspscan tests/amostras/vulneravel   # exit 1 + relatório = funcionou

# API HTTP (opcional, exige extra)
.venv/bin/python -m pip install -e ".[api]"
.venv/bin/python -m owaspscan.api                    # http://127.0.0.1:8000/docs

# Frontend
cd frontend
npm install
npm run dev                                          # http://localhost:5173
```

Windows: troque `.venv/bin/python` por `.venv\Scripts\python`.

## 4. Onde fica o frontend?

`frontend/` — SPA React 19 + Vite 8 + Tailwind 3. Praticamente tudo está em **`frontend/src/App.jsx`** (382 linhas: navegação, tema dark/light, i18n pt/en, abas de análise, páginas estáticas). Traduções em `frontend/src/translate.js`; bootstrap em `frontend/src/main.jsx`. Não há roteador, gerenciador de estado nem componentes separados.

⚠️ Saiba antes de mexer: o frontend é só casca — os botões "Analisar"/"Confirmar upload" não enviam nada (não existe `fetch` em `frontend/src/`), e vários textos exibidos descrevem funcionalidades que não existem (análise de malware/URL, PHP/C++, `@aegis/cli`, `api.aegis.dev`). A integração real seria chamar `POST /analisar` da API (contrato pronto em `TOOL/README.md` §"API HTTP (para o site)").

## 5. Onde fica o backend?

`TOOL/owaspscan/` — pacote Python em camadas, sem framework web no núcleo (stdlib pura). Camadas, de baixo para cima:

```
achado.py        contrato do achado + mapa CWE→OWASP (a base de tudo)
analisador.py    leitura/parse AST resiliente
motor/           taint.py (rastreamento) · catalogo.py (fontes/sinks/sanitizadores)
                 estrutura.py (consultas AST) · credenciais.py · confianca.py
detectores/      11 módulos, 16 CWEs — a "lógica de detecção"
varredura.py     orquestração (executar())
relatorio.py     formatação texto/JSON (módulo puro)
cli.py · api.py  entradas (terminal e HTTP)
metricas.py      autoavaliação contra corpus rotulado
```

## 6. Onde fica o banco?

**Não existe banco de dados.** Nenhuma persistência: a CLI lê o disco do usuário e imprime no terminal; a API grava uploads num `TemporaryDirectory` destruído por requisição (`api.py:123-130`); o frontend só salva o tema no `localStorage`. Detalhado em `docs/banco-de-dados.md`. Se alguém pedir "altera o banco", a resposta hoje é: não há o que alterar — e criar persistência seria uma decisão de arquitetura nova (ADR em `docs/decisoes/`).

## 7. Onde ficam as APIs?

Uma única API HTTP: **`TOOL/owaspscan/api.py`** (FastAPI, extra opcional `[api]`). Endpoints: `POST /analisar` (JSON ou multipart; limites 50 arquivos/1 MB; erros 400/413/415/422) e `GET /saude`. Swagger gerado em `/docs`. Documentação completa: `docs/API.md`. A CLI (`cli.py`) é a outra "interface", sem HTTP.

## 8. Onde ficam as regras de negócio?

O "negócio" é detectar vulnerabilidades. As regras moram em dois lugares:

- **`TOOL/owaspscan/detectores/`** — uma CWE (ou família) por arquivo: `sqli.py`, `xss.py`, `idor.py`, `xxe.py`, `path_traversal.py`, `open_redirect.py`, `csrf.py`, `autorizacao.py`, `autenticacao.py` (6 detectores), `credenciais.py` (2). Cada detector implementa `detectar(arquivo, escopos) -> list[Achado]`.
- **`TOOL/owaspscan/motor/catalogo.py`** — o conhecimento declarativo: o que é fonte não confiável, o que é sink, o que é sanitizador (e quais CWEs cada um neutraliza). **886 linhas de dados, não de lógica** — adicionar framework é acrescentar entradas aqui, sem tocar no motor.

Regras de classificação (inegociáveis): `achado.py` — o mapa `MAPA_CWE_OWASP` é fechado; `criar_achado()` deriva a categoria OWASP, nenhum detector pode inventar classificação. Regras de heurística/confiança: `motor/confianca.py` + `TOOL/README.md` §"Calibração de confianca".

## 9. Onde ficam as configurações?

| O quê | Onde |
| --- | --- |
| Host/porta/CORS da API | env vars `OWASPSCAN_HOST`, `OWASPSCAN_PORTA`, `OWASPSCAN_ORIGENS` (lidas só em `api.py:46,223-224`; todas opcionais) |
| Limites da API | constantes hardcoded `api.py:40-43` (50 arquivos, 1 MB...) |
| Pacote/extras/pytest | `TOOL/pyproject.toml` |
| Build/lint frontend | `frontend/vite.config.js`, `tailwind.config.js` (darkMode: 'class' — o botão de tema depende disso), `postcss.config.js`, `.oxlintrc.json`, `package.json` |
| Estilo/qualidade | `.editorconfig`, `.markdownlint.json`, `.gitignore` (raiz/TOOL/frontend) |

Ficha completa com impacto de cada uma: `docs/configuracao.md`. Não há `.env` no projeto.

## 10. Onde ficam os testes?

`TOOL/tests/` — 19 arquivos pytest (~336 testes), um por camada/detector (`test_taint.py` é o maior, 38). `conftest.py` tem os atalhos (`rodar_detector`, `linhas_esperadas`). O corpus **`TOOL/tests/amostras/`** tem dupla função: fixtures e corpus de avaliação — o gabarito mora em comentários nas próprias amostras (`# achado: CWE-89` na linha do sink; `# limitacao: CWE-89 ...` para falha conhecida). **O frontend não tem nenhum teste.**

## 11. Onde começar a investigar um bug?

Pela camada do sintoma:

| Sintoma | Comece por | Depois |
| --- | --- | --- |
| Falso negativo (não detectou o que devia) | a amostra em `tests/amostras/`: o caso está rotulado `# achado:` ou `# limitacao:`? Se for limitação declarada (fluxo interprocedural, template `.html`), é comportamento conhecido — `TOOL/README.md` §Limitações | `motor/catalogo.py` (a fonte/sink está catalogada?) → `motor/taint.py` (a contaminação propaga?) → detector da CWE |
| Falso positivo (detectou o que não devia) | detector da CWE em `detectores/` → falta sanitizador ou guarda no catálogo? | `motor/confianca.py` |
| Classificação errada (CWE/OWASP/severidade) | `achado.py` (mapa) e o `criar_achado(...)` do detector | `tests/test_contrato.py` |
| CLI: exit code/relatório errado | `cli.py` → `relatorio.py` | `varredura.py` |
| API: status code/mensagem | `api.py` (validações em `montar_envios`/`nome_seguro`) | `tests/test_api.py` reproduz quase tudo |
| API: resultado difere da CLI | não deveria — ambos chamam `varredura.executar()`; suspeite da camada de envio | `varrer()` em `api.py:123` |
| Métricas mudaram | `metricas.py` → gabarito das amostras foi editado? | — |
| Frontend: tema/idioma/layout | `App.jsx` (estado local) e `translate.js` | `tailwind.config.js` (darkMode) |
| Frontend: "análise não funciona" | não é bug: a integração não existe (item 4) | — |

Ferramentas: reproduzir com `python -m owaspscan <amostra>`, isolar com os helpers do `conftest.py` (`rodar_detector` sobre código em memória), confirmar com `pytest tests/test_<area>.py -v`.

## 12. Onde implementar uma nova funcionalidade?

**Novo detector (nova CWE)** — o caminho mais comum:

1. Decida a técnica: taint (fonte→sink), estrutural ou heurística (candidato). Modelos: `detectores/sqli.py` (taint mínimo, 79 linhas), `detectores/xxe.py` (estrutural+taint), `detectores/idor.py` (heurística com `PREFIXO_CANDIDATO`).
2. Se preciso, declare fontes/sinks/sanitizadores novos em `motor/catalogo.py` (dado, não lógica).
3. Crie `detectores/<nome>.py` com um dataclass frozen e `detectar(arquivo, escopos)`; emita achados **só** via `criar_achado()`; confiança via `motor/confianca.py`.
4. Se for CWE nova: adicione ao `MAPA_CWE_OWASP` em `achado.py` **com a categoria oficial do OWASP 2021** e atualize `tests/test_contrato.py`.
5. Registre em `varredura.detectores_padrao()` (ordem do relatório).
6. Testes: `tests/test_<nome>.py` + amostras rotuladas em `tests/amostras/` (vulnerável E segura). Rode `pytest` e `python -m owaspscan.metricas tests/amostras` — precisão não pode cair.
7. Atualize a tabela de cobertura do `TOOL/README.md`.

**Processo da casa** (`TOOL/CLAUDE.md`, obrigatório): fases pequenas; ao fim de cada fase escrever o teste, rodar pytest e mostrar a saída; cada fase que passa termina com um git commit; explicar decisões de design em 1-2 linhas antes de codar; se houver dúvida de escopo, perguntar em vez de assumir.

**Outras funcionalidades:** nova consulta estrutural → `motor/estrutura.py`; novo formato de configuração → `configuracao.py` + `formato_de()` (+ validação de extensão em `api.py:85-90` e testes); nova página/seção web → `App.jsx` (+ textos em `translate.js` nos DOIS idiomas); integração frontend↔API → `App.jsx` chamando `POST /analisar` (exemplos prontos em `TOOL/README.md` §API HTTP) + decidir URL da API (proxy no `vite.config.js` ou env `VITE_*`).

## 13. Onde alterar a API?

`TOOL/owaspscan/api.py` — arquivo único (handler, validação, modelos pydantic, CORS, limites). Regras: mantenha o contrato de resposta = `relatorio.para_dict()` (a CLI e a API devolvem o mesmo JSON); limites novos viram constantes + teste em `tests/test_api.py`; o núcleo não pode ganhar dependência de FastAPI (extra `[api]` é isolado de propósito). Atualize `docs/API.md` junto.

## 14. Onde alterar o banco?

Não existe banco (item 6). Se a necessidade for real (ex.: histórico de análises no site), é decisão de arquitetura: registrar ADR em `docs/decisoes/` (template disponível) antes de qualquer código, e lembrar que a promessa atual de privacidade ("nada é retido") está nos textos do produto.

## 15. Onde alterar a interface?

Tudo em `frontend/src/App.jsx`: navegação por estado (`paginaAtual`, sem router), abas (`abaAtiva`), tema (classe `dark` no `<html>` — exige `darkMode: 'class'` do `tailwind.config.js`), páginas estáticas (`conteudosPagina`, texto puro com `###` simulando heading). Textos visíveis: **sempre nos dois idiomas** em `translate.js` (existem strings hardcoded em português dentro do `App.jsx` — inconsistência conhecida; ao mexer, prefira mover para `translate.js`). Estilo: classes Tailwind inline; `index.css` só tem as diretivas. Antes de commitar: `npm run lint` (oxlint com `react/rules-of-hooks` como erro) e `npm run build`.

## 16. Como executar os testes?

```bash
cd TOOL
.venv/bin/python -m pytest -v              # tudo (~336 testes)
.venv/bin/python -m pytest tests/test_sqli.py -v          # um arquivo
.venv/bin/python -m pytest -k "idor" -v                   # por nome
.venv/bin/python -m owaspscan.metricas tests/amostras     # métricas do motor (P/R/F1)
cd ../frontend && npm run lint                            # lint do frontend (não há testes)
```

Requer extra `[dev]` instalado (pytest + httpx). `test_api.py` pula sozinho se o extra `[api]` não estiver instalado (`pytest.importorskip`). Config em `pyproject.toml` (`testpaths = ["tests"]`, saída `-q` por padrão).

## 17. Como verificar logs?

Não há sistema de logs do projeto. O que existe:

- **CLI**: stdout (relatório; com `--json`, o JSON vai ao stdout e o resumo ao stderr) e mensagens de erro no stderr.
- **API**: logging padrão do Uvicorn no console (linhas de acesso/erro do servidor); erros de validação voltam como `{"detail": ...}` na resposta HTTP — não são logados pela aplicação.
- **Frontend**: console do navegador (React DevTools; nenhum log próprio).
- Healthcheck: `curl http://127.0.0.1:8000/saude`.

Se precisar depurar a análise em si, o caminho não é log: é reproduzir com a amostra mínima e inspecionar via `conftest.rodar_detector()` / `analisar_texto()` + `analisar_taint()` no REPL (padrão usado pelos próprios testes).

## 18. Quais arquivos são mais importantes?

Ordem de leitura recomendada para as primeiras semanas:

1. `TOOL/CLAUDE.md` — princípios inegociáveis (AST nunca regex, contrato fixo, IDOR heurístico, honestidade > cobertura)
2. `TOOL/README.md` — cobertura, limitações declaradas, calibração de confiança, uso
3. `TOOL/owaspscan/achado.py` — o contrato que atravessa tudo
4. `TOOL/owaspscan/varredura.py` — o pipeline inteiro em 130 linhas (`executar()`)
5. `TOOL/owaspscan/motor/taint.py` + `motor/catalogo.py` — o coração da detecção
6. `TOOL/owaspscan/detectores/sqli.py` — o menor detector completo (padrão a copiar)
7. `TOOL/owaspscan/api.py` + `cli.py` — as duas entradas
8. `TOOL/owaspscan/relatorio.py` — o formato de saída (contrato com consumidores)
9. `frontend/src/App.jsx` — o frontend inteiro
10. `docs/arquitetura.md`, `docs/estrutura.md`, `docs/API.md`, `docs/SEGURANCA.md` — o mapa documental

## 19. Quais partes são mais sensíveis?

Mexeu aqui, redobre o cuidado (e os testes):

| Área | Por quê |
| --- | --- |
| `achado.py` — `MAPA_CWE_OWASP` | Contrato fechado: classificação errada contamina TODOS os achados. Só estender com categoria oficial OWASP 2021 + atualização de `test_contrato.py` |
| `motor/taint.py` — loop de ponto fixo | Sutil: qualquer mudança afeta todos os detectores de taint; pode introduzir falsos negativos silenciosos (o pior erro para uma ferramenta de segurança — princípio do `CLAUDE.md`) |
| `motor/catalogo.py` — sanitizadores | Cada sanitizador declara quais CWEs neutraliza. Tratar sanitização como absoluta = falso negativo (ex.: `html.escape` NÃO defende SQLi) |
| `api.py` — `nome_seguro`/`montar_envios` | Fronteira contra entrada hostil (path traversal, abuso de tamanho). Enfraquecer aqui abre vulnerabilidade real no produto |
| `motor/credenciais.py` — `mascarar` | Se regressar, a ferramenta passa a vazar os segredos que detecta |
| `tests/amostras/` — comentários de gabarito | São o ground truth das métricas; editar rótulos sem justificativa "maquia" precisão/recall (o README explica a política) |
| `varredura.py` — `detectores_padrao()` | Ordem define o relatório; esquecer de registrar detector novo = ele nunca roda |
| `relatorio.py` — `para_dict()` | É o contrato consumido por CLI `--json`, API e (futuramente) frontend; mudar campos quebra consumidores |
| `tailwind.config.js` — `darkMode: 'class'` | O sistema de temas do `App.jsx` depende disso |

**Sensível por política**: nada de credenciais reais no repositório (`SECURITY.md`); fixtures com segredos fictícios só em `tests/amostras/`; não commitar `.env`/`relatorio.json` (já no `.gitignore`).

## Primeiros passos sugeridos (checklist do dia 1)

1. Ler `TOOL/CLAUDE.md` e `TOOL/README.md` (30 min).
2. Setup do item 3 e rodar `pytest -v` — tudo verde.
3. Rodar `python -m owaspscan tests/amostras/vulneravel` e ler o relatório comparando com as amostras.
4. Rodar `python -m owaspscan.metricas tests/amostras` e entender o gabarito embutido.
5. Abrir `detectores/sqli.py` e seguir o fluxo com `docs/fluxos.md` §Pipeline interno.
6. Subir a API (`[api]`), abrir `/docs` e enviar o exemplo de SQL Injection.
7. Subir o frontend e constatar o estado de protótipo (item 4).
8. Ler `docs/arquitetura.md` §Riscos — as lacunas conhecidas são candidatas naturais a primeiro trabalho (ex.: integrar frontend↔API).
