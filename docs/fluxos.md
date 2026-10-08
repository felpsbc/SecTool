# Fluxos do sistema

Principais fluxos de negócio do AEGIS, mapeados passo a passo a partir do código (commit `a90120a`). Cada fluxo indica os arquivos responsáveis por etapa, validações, dados envolvidos e tratamento de erros.

## Visão geral e priorização

O "negócio" do sistema é um só: **receber código-fonte, analisá-lo estaticamente e devolver um relatório de vulnerabilidades**. Isso acontece por duas entradas (CLI e API HTTP), com um processo interno de avaliação (métricas) e um frontend ainda não integrado.

| # | Fluxo | Ator | Importância | Entrada → Saída |
| --- | --- | --- | --- | --- |
| 1 | **Análise via CLI** | desenvolvedor / CI | ★ principal | caminho no disco → relatório no terminal + exit code |
| 2 | **Análise via API HTTP** | site / cliente HTTP | ★ principal | upload/JSON → relatório JSON |
| 3 | **Avaliação do motor** | equipe (processo manual) | alta (qualidade) | corpus rotulado → tabela de precisão/recall |
| 4 | **Healthcheck** | monitoramento | baixa | requisição GET → status/versão |
| 5 | **Navegação no frontend** | usuário web | média (estado atual: protótipo) | cliques → mudança de estado local |

Os fluxos 1 e 2 compartilham o mesmo **núcleo de processamento** (seção [Pipeline interno](#pipeline-interno-comum-aos-fluxos-1-e-2)), descrito uma vez.

Fluxos que **não existem** (verificados no código): login/cadastro, histórico de análises, compartilhamento com comunidade, cobrança, webhook, job agendado. Textos do frontend mencionam alguns deles, mas nenhuma linha de código os implementa (ver fluxo 5).

---

## Fluxo 1 — Análise via CLI (principal)

**Exemplo condutor**: o desenvolvedor quer verificar um projeto Flask em `~/projetos/loja`:

```bash
python -m owaspscan ~/projetos/loja
```

### 1. Como começa

O usuário executa `python -m owaspscan caminho [--json]`. O Python carrega `TOOL/owaspscan/__main__.py`, que chama `cli.main()` e converte o retorno em exit code (`raise SystemExit(main())`).

### 2. Componente que recebe

`cli.py` — `montar_parser()` (`cli.py:29-49`) define a interface: argumento posicional `caminho` (obrigatório), flags `--json` e `--versao`. `main()` (`cli.py:52-71`) é o ponto de entrada.

### 3. Validações

| Validação | Onde | Falha |
| --- | --- | --- |
| argv bem-formado (caminho presente, flags válidas) | `argparse` em `montar_parser()` | argparse imprime uso e sai com código 2 |
| caminho existe no disco | `cli.py:56-58` | `erro: caminho nao encontrado: X` no stderr → **exit 2** |
| (arquivos individuais) sintaxe/codificação/IO válidos | `analisador.analisar_arquivo` (`analisador.py:112-151`) | **não é erro fatal**: vira `FalhaDeLeitura` registrada no relatório |

### 4. Funções executadas (cadeia)

```
cli.main()                                    cli.py:52
 └→ varredura.executar(raiz)                  varredura.py:92   ← orquestração
     ├→ analisador.analisar_diretorio()       analisador.py:154
     │   └→ descobrir_arquivos()              analisador.py:98  (rglob *.py, ignora .venv/node_modules/...)
     │   └→ analisar_arquivo() ×N             analisador.py:112 (tokenize.open + ast.parse resiliente)
     ├→ para cada ArquivoAnalisado:           varredura.py:110-113
     │   ├→ motor.taint.analisar_taint()      taint.py:281      (um Escopo por módulo/classe/função)
     │   └→ detector.detectar() ×15           detectores/*      (ordem fixa de detectores_padrao, varredura.py:44)
     └→ se incluir_configuracao:              varredura.py:115-121
         ├→ configuracao.ler_diretorio()      configuracao.py:247 (.env/YAML/JSON/INI/TOML/.properties ≤1MB)
         └→ DetectorCredenciaisEmConfiguracao detectores/credenciais.py:280
 └→ relatorio.formatar_texto(varredura)       relatorio.py:103
 └→ (com --json) relatorio.para_dict()        relatorio.py:167
```

### 5. Dados consultados ou modificados

- **Consultados (leitura apenas)**: arquivos `.py` e de configuração sob o caminho informado. O código analisado **nunca é executado nem modificado** — apenas lido e parseado em memória.
- **Modificados**: nada em disco. Os dados "produzidos" vivem em memória: `ArquivoAnalisado` → `Escopo`/`Procedencia` → `Achado` → `Varredura` (todas dataclasses; `Achado` e `Varredura` são frozen/imutáveis).
- **Saída em disco só se o usuário redirecionar** (ex.: `--json > relatorio.json` — o `.gitignore` do TOOL já exclui esse arquivo).

### 6. Componentes participantes

`__main__.py` → `cli.py` → `varredura.py` → `analisador.py` + `motor/` (taint, catalogo, estrutura, confianca, credenciais) + `detectores/` (11 módulos) + `configuracao.py` → `relatorio.py`. (Fichas individuais em `docs/estrutura.md`.)

### 7. Como o resultado é retornado

- **Modo texto** (padrão): `formatar_texto()` imprime no stdout um resumo executivo: cabeçalho (raiz, data, contagem de arquivos), totais por severidade/OWASP, seção "ACHADOS RASTREADOS POR TAINT", seção "CANDIDATOS HEURISTICOS (requerem revisão manual)", recomendações por CWE e arquivos não analisados.
- **Modo `--json`**: JSON de `para_dict()` no **stdout** (limpo para `| jq`), resumo em texto no **stderr** (`cli.py:63-67`).
- **Exit code** (`cli.py:71`, constantes em `cli.py:24-26`): `0` sem achado de severidade alta · `1` com pelo menos um achado alto · `2` erro de uso. Candidatos heurísticos (confiança baixa) **não** alteram o exit code — decisão documentada: "não seria honesto quebrar um build com base em suposição". É esse exit code que permite uso em CI/pre-commit (`if [ $? -eq 1 ]; then bloqueia merge`).

### 8. Tratamento de erros

| Erro | Comportamento | Onde |
| --- | --- | --- |
| caminho inexistente | mensagem no stderr, exit 2 | `cli.py:56-58` |
| arquivo com sintaxe inválida / encoding ruim / IO | `FalhaDeLeitura` listada na seção "ARQUIVOS NAO ANALISADOS" do relatório; varredura continua | `analisador.py:120-147`, `relatorio.py:156-161` |
| CWE desconhecida ou classificação incoerente | `ClassificacaoInvalida` (exceção) — protege o contrato; na prática impossível via detectores, pois todos usam `criar_achado()` | `achado.py:149-172,196-201` |
| falha no detector de configuração | também vira `FalhaDeLeitura` agregada | `varredura.py:115-118` |

---

## Fluxo 2 — Análise via API HTTP (principal)

**Exemplo condutor**: o site envia código colado pelo usuário:

```js
fetch("http://127.0.0.1:8000/analisar", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ codigo: "from flask import request\nimport sqlite3\ndef v():\n  sqlite3.connect('x.db').execute('SELECT * FROM t WHERE id=' + request.args['id'])\n" })
});
```

### 1. Como começa

Requisição HTTP `POST /analisar` chega ao servidor Uvicorn (subido por `api.main()`, `api.py:218-225`, host/porta das env vars). Antes, se for chamada de navegador cross-origin, o `CORSMiddleware` responde o preflight `OPTIONS` (`api.py:67-72`).

### 2. Componente que recebe

`api.py` — handler `analisar(request)` (`api.py:191-200`). Não há router/service separado: o handler faz o dispatch e delega a validação e a varredura.

### 3. Validações (em camadas, todas antes de analisar)

| Ordem | Validação | Onde | Erro |
| --- | --- | --- | --- |
| 1 | `Content-Type` ∈ {`application/json`, `multipart/form-data`, `application/x-www-form-urlencoded`} | `api.py:192-198` | **415** |
| 2a | (JSON) corpo é JSON válido e segue o esquema pydantic `Envio` (`codigo?`, `nome?`, `arquivos?[{nome, conteudo}]`) | `_envios_de_json`, `api.py:133-141` | **422** com lista de erros |
| 2b | (form) tetos do parser Starlette: `max_files=51`, `max_part_size=2MB`; campo `arquivos` deve conter uploads, não texto | `_envios_de_formulario`, `api.py:144-161` | **400** |
| 3 | ≤ 50 arquivos por envio | `montar_envios`, `api.py:102-103` | **413** |
| 4 | nome do arquivo reduzido ao nome-base; não vazio/`.`/`..`; extensão `.py` ou de configuração | `nome_seguro`, `api.py:75-91` | **400** |
| 5 | sem nomes duplicados (após redução) | `api.py:111-112` | **400** |
| 6 | ≤ 1.000.000 bytes por arquivo (multipart: lê 1 byte extra para detectar sem baixar tudo) | `api.py:113-116,156` | **413** |
| 7 | envio não vazio (algo em `codigo` ou `arquivos`) | `api.py:118-119` | **400** |

Validação de *conteúdo* de código (sintaxe inválida) **não** gera erro HTTP — vira dado na resposta (passo 8).

### 4. Funções executadas

```
analisar(request)                              api.py:191
 ├→ _envios_de_json / _envios_de_formulario    api.py:133/144   (parse + validação)
 ├→ montar_envios(...)                         api.py:98        → dict {nome_seguro: bytes}
 └→ run_in_threadpool(varrer, envios)          api.py:200       ← análise CPU-bound fora do event loop
     varrer(envios)                            api.py:123-130
      ├→ tempfile.TemporaryDirectory("owaspscan-")
      ├→ write_bytes por arquivo               api.py:127-128
      ├→ varredura.executar(pasta)             varredura.py:92  ← MESMO núcleo do fluxo 1
      ├→ (with sai → pasta destruída)
      └→ relatorio.para_dict(replace(varredura, raiz="envio"))   api.py:130
```

### 5. Dados consultados ou modificados

- **Recebidos**: código-fonte como texto (JSON) ou bytes (upload).
- **Modificados em disco**: apenas dentro do `TemporaryDirectory` — arquivos gravados (`api.py:127-128`), lidos pelo motor, **destruídos ao final da requisição** (`with`, `api.py:125`). Nada persiste; nenhum banco é acessado (`docs/banco-de-dados.md`).
- **Em memória**: mesmas entidades do fluxo 1 (`ArquivoAnalisado` → `Escopo` → `Achado` → `Varredura`).
- **Proteções de dados**: nomes de arquivo perdem diretórios (anti path traversal — `../../etc/app.py` vira `app.py`, testado em `test_api.py:101-107`); o caminho real da pasta temporária nunca aparece na resposta (`raiz` é reescrita para `"envio"`, `api.py:43,130`); segredos detectados (CWE-798) chegam **mascarados** no `trecho` (`motor/credenciais.py:246`).

### 6. Componentes participantes

`CORSMiddleware` → handler `analisar` → validadores de `api.py` → threadpool → `varrer` → **núcleo idêntico ao fluxo 1** (`varredura`, `analisador`, `motor/`, `detectores/`, `configuracao`) → `relatorio.para_dict`.

### 7. Como o resultado é retornado

Resposta `200 OK` `application/json` — exatamente o contrato de `para_dict()` (o mesmo do `--json` da CLI): `{ferramenta, versao, raiz:"envio", momento, varredura{arquivos_analisados, arquivos_de_configuracao, arquivos_com_falha, falhas[]}, resumo{total, rastreados_por_taint, candidatos_heuristicos, por_severidade, por_owasp, por_cwe, por_arquivo}, achados[...]}` com os 10 campos fixos por achado. No exemplo condutor: `achados[0]` com `cwe:"CWE-89"`, `owasp:"A03:2021 Injection"`, `severidade:"alta"`, `confianca:"alta"`. JSON e formulário produzem resultado idêntico (`test_api.py:153-156`).

### 8. Tratamento de erros

| Situação | HTTP | Corpo |
| --- | --- | --- |
| envio vazio / nome inválido / tipo não suportado / duplicado / texto em campo de arquivo | 400 | `{"detail": "mensagem em português"}` |
| > 50 arquivos ou > 1 MB por arquivo | 413 | idem |
| Content-Type não suportado | 415 | idem |
| JSON malformado ou fora do esquema | 422 | `{"detail": [erros pydantic sem URLs internas]}` (`api.py:136-138`) |
| método errado na rota (ex. `GET /analisar`) | 405 | padrão FastAPI |
| código com sintaxe inválida | **200** | registrado em `varredura.falhas[]` com `motivo:"sintaxe"` (`test_api.py:58-62`) |
| erro interno inesperado | 500 | padrão Starlette — não esperado: o motor é resiliente por construção (`FalhaDeLeitura`) |

Limitações de robustez conhecidas (sem rate limiting, corpo JSON lido em memória antes do limite de tamanho): `docs/API.md` §Limitações.

---

## Pipeline interno (comum aos fluxos 1 e 2)

O coração do negócio, executado por `varredura.executar()` (`varredura.py:92-130`) para cada arquivo `.py`:

```
ArquivoAnalisado (AST + fonte + origem)
  ↓  motor/taint.analisar_taint()                     taint.py:281
  │   • um Escopo por módulo/classe/função (fronteiras: FunctionDef/AsyncFunctionDef/ClassDef)
  │   • sementes: fontes do catálogo (request.args, request.form...) + parâmetros de rota Flask
  │   • propagação por PONTO FIXO: repete as atribuições até o conjunto de contaminados
  │     estabilizar → independente da ordem textual (taint.py:310-328)
  │   • cada nome contaminado carrega Procedencia {fonte, sanitizadores, via_chamada, condicional}
  ↓
15× detector.detectar(arquivo, escopos)               detectores/*
  │   • taint (sqli, xss, idor, path_traversal, open_redirect, senha em texto puro):
  │     procura SINKS do catálogo nos nós do escopo (nos_do_escopo evita duplicatas),
  │     verifica contaminação dos argumentos e SANITIZAÇÃO relevante para a CWE
  │     (sanitizador que neutraliza a CWE REMOVE o achado — não rebaixa confiança)
  │   • estruturais/heurísticos (xxe, csrf, autorizacao, autenticacao, credenciais):
  │     consultas de motor/estrutura (imports, decorators, rotas, config) — sem taint ou parcial
  │   • todo achado nasce de criar_achado() → classificação CWE→OWASP imposta pelo mapa,
  │     nunca inventada pelo detector (achado.py:180-213)
  │   • confiança calibrada por motor/confianca (alta/média; baixa = candidato heurístico)
  ↓
list[Achado] → ordenar_achados (arquivo, linha, cwe)  varredura.py:125
  + achados de configuração (CWE-798, segredo mascarado)
  ↓
Varredura (imutável) → relatorio (texto/JSON)
```

**Exemplo mínimo do pipeline** (SQL Injection do exemplo do fluxo 2):

1. `analisador` parseia o módulo; 2. `catalogo` reconhece `request.args` como fonte e `sqlite3...execute` como `SinkSql`; 3. `taint` semeia `request.args["id"]` e propaga: a concatenação `"SELECT..." + request.args["id"]` contamina o argumento do `execute` (Procedencia{fonte:"request.args", sanitizadores:∅, via_chamada:False, condicional:False}); 4. `DetectorSqlInjection` casa a chamada com o sink, vê contaminação sem `int()`/parametrização → `criar_achado(cwe="CWE-89", severidade="alta", confianca="alta", ...)`; 5. `achado.py` deriva `owasp="A03:2021 Injection"` do mapa; 6. relatório exibe com recomendação de correção.

---

## Fluxo 3 — Avaliação do motor (processo da equipe)

**Exemplo**: `python -m owaspscan.metricas tests/amostras`

1. **Começo**: execução manual do módulo `metricas.py` (`main()`, `metricas.py:172`) pela equipe, para medir qualidade após mudanças.
2. **Recebe**: `metricas.main(argv)` — argumento é o diretório do corpus.
3. **Validações**: diretório acessível; gabarito bem-formado (comentários `# achado: CWE-x` / `# limitacao: CWE-x` nas linhas de sink das amostras).
4. **Funções**: `carregar_gabarito()` (`metricas.py:57`) extrai o esperado dos comentários; `varredura.executar()` roda o motor no corpus; `avaliar()` (`metricas.py:107`) confronta achados × gabarito.
5. **Dados**: **consulta** `tests/amostras/` (25 `.py` + 9 de configuração, incluindo 1 com erro de sintaxe proposital); nada é modificado. Regra de honestidade: `# limitacao` (falha conhecida, ex.: fluxo interprocedural) **conta como falso negativo** — "declarar a falha não a transforma em acerto" (`metricas.py:9-13`).
6. **Componentes**: `metricas.py` → `configuracao.descobrir_configuracoes` + `varredura.executar` (motor completo) → `achado.MAPA_CWE_OWASP` (para o universo de CWEs).
7. **Resultado**: tabela por CWE com VP/FP/FN, precisão, recall e F1 no stdout (`formatar_tabela`, `metricas.py:148`). Valores de referência declarados: precisão 1.00, recall 0.98, F1 0.99 (corpus próprio — mede consistência interna, não generalização).
8. **Erros**: amostra ilegível segue a resiliência do núcleo (`FalhaDeLeitura`); amostra sem gabarito simplesmente não contribui com itens esperados.

Este fluxo também alimenta os **testes automatizados**: `tests/conftest.py` usa `carregar_gabarito` (`linhas_esperadas`, `linhas_de_limitacao`) para que cada `test_*.py` confira detectores contra as mesmas amostras rotuladas.

---

## Fluxo 4 — Healthcheck (`GET /saude`)

1. **Começo**: requisição `GET /saude` (monitoramento ou verificação manual pós-deploy local).
2. **Recebe**: handler `saude()` (`api.py:164-166`).
3. **Validações**: nenhuma necessária (sem parâmetros).
4. **Funções**: apenas `saude()` — **não** invoca o motor de análise.
5. **Dados**: nenhuma consulta/modificação; lê a constante `VERSAO` importada de `varredura.py:40`.
6. **Componentes**: `api.py` somente.
7. **Resultado**: `200` `{"status": "ok", "versao": "0.2.0"}`.
8. **Erros**: rota não pode falhar por entrada; se o processo estiver fora do ar, a falha é de conexão (fora do escopo do código).

---

## Fluxo 5 — Navegação no frontend (estado atual: protótipo)

**Exemplo**: usuário abre o site local (`npm run dev`), alterna tema e idioma, arrasta arquivos.

1. **Começo**: navegador carrega `frontend/index.html` → `src/main.jsx` monta `<App/>` (React StrictMode) no `#root`.
2. **Recebe**: `frontend/src/App.jsx` — componente único que concentra todo o estado e renderização.
3. **Validações**: nenhuma relevante; drag & drop aceita qualquer arquivo no estado local (`handleDrop`, `App.jsx:78-84`), sem checagem de tipo/tamanho (a API faria essa validação — se fosse chamada).
4. **Funções/estado**: `useState` para `idioma`, `tema` (inicializado de `localStorage['aegis-tema']`, `App.jsx:33`), `abaAtiva`, `paginaAtual`, `arquivos`, `arrastando`; `useEffect` aplica a classe `dark` no `<html>` e persiste o tema (`App.jsx:47-62`); `navegarPara()` troca a "página" sem roteador (`App.jsx:98-102`); `renderizarConteudo()` decide home vs. páginas estáticas (`App.jsx:105-315`).
5. **Dados**: `traducoes` de `src/translate.js` (i18n pt/en); textos das páginas estáticas hardcoded em `conteudosPagina` (`App.jsx:269-294`); **única escrita persistente**: `localStorage['aegis-tema']`. Nenhum dado sai do navegador — **não há `fetch`/XHR em todo o `frontend/src/`**.
6. **Componentes**: `main.jsx`, `App.jsx` (ícones SVG internos, `AIcon`), `translate.js`, `index.css` (Tailwind).
7. **Resultado**: UI reage (tema, idioma, abas file/url/snippet/cli, remoção de chips de arquivo, páginas docs/termos/privacidade/FAQ/scripts). Os botões "Confirmar upload", "Pesquisar" e "Analisar" **não produzem análise** — não têm handler de envio.
8. **Erros**: não há caminho de erro de rede (nenhuma chamada); erros possíveis só de runtime React. ⚠️ Inconsistências documentadas: os textos prometem funcionalidades inexistentes (malware/URL/domínio, múltiplas linguagens, `@aegis/cli`, `api.aegis.dev`) — registradas em `docs/arquitetura.md` §Riscos.

**Fluxo futuro previsto** (contrato já publicado em `TOOL/README.md` §"API HTTP (para o site)", ainda não implementado): `App.jsx` coletaria `arquivos`/textarea → `fetch POST /analisar` (FormData ou JSON) → renderizaria `resultado.resumo`/`resultado.achados`. É a integração natural entre os fluxos 5 e 2.

---

## Resumo do tratamento de erros (todos os fluxos)

| Camada | Filosofia | Mecanismo |
| --- | --- | --- |
| Entrada CLI | falha rápida e clara | stderr + exit 2 (`cli.py:56-58`) |
| Entrada API | nunca aceitar dado inválido, mensagens em português | `HTTPException` 400/413/415/422 com `detail` (`api.py`) |
| Leitura de arquivos (núcleo) | **arquivo quebrado é dado, não exceção** — uma varredura não morre por um arquivo | `FalhaDeLeitura` (`analisador.py:112-151`) listada no relatório |
| Classificação (núcleo) | falha dura — contrato é inegociável | `ClassificacaoInvalida` no `__post_init__` (`achado.py:149-172`) |
| Resultado | honestidade: candidatos não quebram build; limitações contam como FN na avaliação | exit code ignora confiança baixa (`cli.py:10-11`); `metricas.py:9-13` |

## Referências

- Implementações citadas: `TOOL/owaspscan/` (`cli.py`, `api.py`, `varredura.py`, `analisador.py`, `relatorio.py`, `achado.py`, `configuracao.py`, `metricas.py`, `motor/`, `detectores/`) e `frontend/src/`
- Comportamentos confirmados por: `TOOL/tests/` (em especial `test_integracao.py`, `test_api.py`, `test_metricas.py`)
- Documentos complementares: `docs/arquitetura.md` (componentes), `docs/API.md` (contrato HTTP), `docs/banco-de-dados.md` (ausência de persistência), `docs/estrutura.md` (papel de cada arquivo)
