# API — Documentação técnica

Documentação completa da única API do projeto AEGIS: a camada HTTP do analisador estático `owaspscan`, implementada em **FastAPI** no arquivo `TOOL/owaspscan/api.py` (229 linhas). Todas as informações abaixo foram confirmadas no código-fonte e nos testes (`TOOL/tests/test_api.py`, 26 testes); comportamentos não confirmáveis estão marcados **[NECESSÁRIO CONFIRMAR]**.

## Visão geral

| Item | Valor | Origem |
| --- | --- | --- |
| Tecnologia | FastAPI + Uvicorn (extra opcional `[api]` do `pyproject.toml`; o núcleo não depende dela) | `api.py:19-21`, `pyproject.toml:9` |
| Versão | `0.2.0` (constante `VERSAO` de `varredura.py:40`, usada no `FastAPI(version=...)`) | `api.py:62-66` |
| Base URL padrão | `http://127.0.0.1:8000` (configurável via `OWASPSCAN_HOST`/`OWASPSCAN_PORTA`) | `api.py:218-225` |
| Documentação interativa | Swagger UI em `/docs`, ReDoc em `/redoc`, esquema em `/openapi.json` (rotas automáticas do FastAPI; `/openapi.json` é customizado para registrar o schema `ArquivoEnviado` — `api.py:203-215`) | padrão FastAPI + `test_api.py:193-197` |
| Subir o servidor | `.venv/bin/python -m owaspscan.api` | `api.py:228-229`, `TOOL/README.md` |
| Banco de dados | **nenhum** — nenhum endpoint acessa banco; uploads vivem numa pasta temporária destruída por requisição | `api.py:123-130` |
| Autenticação | **nenhuma** — API aberta | ver [Autenticação e autorização](#autenticação-e-autorização) |

### Endpoints existentes (inventário completo)

| Método | Rota | Finalidade | Autenticação | Implementação |
| --- | --- | --- | --- | --- |
| `GET` | `/saude` | healthcheck: status e versão | nenhuma | `api.py:164-166` |
| `POST` | `/analisar` | analisa código enviado e devolve o relatório da varredura | nenhuma | `api.py:169-200` |
| `OPTIONS` | (qualquer rota) | preflight CORS, respondido automaticamente pelo middleware | nenhuma | `CORSMiddleware` (`api.py:67-72`; testado em `test_api.py:181-191`) |
| `GET` | `/docs` · `/redoc` · `/openapi.json` | documentação OpenAPI gerada pelo FastAPI | nenhuma | automáticas do framework |

Não existem outros endpoints — nenhuma outra rota é registrada no código.

---

## `GET /saude`

| | |
| --- | --- |
| Finalidade | healthcheck simples (o único mecanismo de monitoramento do projeto) |
| Autenticação | nenhuma |
| Parâmetros / query / headers / body | nenhum |
| Função chamada | `saude()` (`api.py:164-166`) — não invoca o motor de análise |
| Banco de dados | nenhum |

**Resposta `200 OK`** (`application/json`):

```json
{"status": "ok", "versao": "0.2.0"}
```

**Erros**: nenhum específico — rota não pode falhar por entrada do usuário.

Exemplo:

```bash
curl http://127.0.0.1:8000/saude
```

---

## `POST /analisar`

| | |
| --- | --- |
| Finalidade | receber código-fonte (colado e/ou arquivos) e devolver o relatório completo da análise estática — exatamente o mesmo JSON de `python -m owaspscan --json` |
| Autenticação | nenhuma |
| Query parameters | nenhum |
| Headers | `Content-Type` obrigatório: `application/json`, `multipart/form-data` **ou** `application/x-www-form-urlencoded` (qualquer outro → `415`); `Origin` para CORS |
| Body | um dos dois formatos abaixo (campos idênticos nos dois) |
| Função chamada | `analisar()` (`api.py:191-200`) → `_envios_de_json()`/`_envios_de_formulario()` → `montar_envios()` → `run_in_threadpool(varrer)` → `varredura.executar()` → `relatorio.para_dict()` |
| Banco de dados | nenhum — o envio é gravado em `tempfile.TemporaryDirectory(prefix="owaspscan-")`, analisado e a pasta é destruída ao final (`api.py:123-130`); nada é persistido |
| Garantia de segurança | o código enviado **nunca é executado**, apenas parseado (AST); o caminho temporário do servidor nunca aparece na resposta (`raiz` é substituída por `"envio"`, `api.py:43,130`; testado em `test_api.py:53-56`) |

### Formato do body

Campos (mesmos nos dois Content-Types):

| Campo | Tipo | Obrigatório | Padrão | Descrição |
| --- | --- | --- | --- | --- |
| `codigo` | string | não* | — | código-fonte colado; espaços-only/ vazio é ignorado |
| `nome` | string | não | `"codigo.py"` | nome exibido para o código colado (`NOME_DO_CODIGO_COLADO`, `api.py:42`) |
| `arquivos` | lista | não* | `[]` | arquivos a analisar (ver abaixo) |

\* Pelo menos um conteúdo efetivo é necessário: sem `codigo` não-vazio e sem `arquivos`, a resposta é `400` ("envie codigo no campo 'codigo' ou arquivos no campo 'arquivos'", `api.py:118-119`).

**Formato 1 — JSON** (`application/json`), modelo pydantic `Envio`/`ArquivoEnviado` (`api.py:49-59`):

```json
{
  "codigo": "from flask import request\n...",
  "nome": "app.py",
  "arquivos": [
    {"nome": "views.py", "conteudo": "..."},
    {"nome": ".env", "conteudo": "SECRET_KEY=\"...\"\n"}
  ]
}
```

- `arquivos[].nome` (string, obrigatório no objeto) e `arquivos[].conteudo` (string, obrigatório — texto do arquivo lido como UTF-8 pelo cliente).
- JSON malformado ou fora do esquema (ex.: `{"nome": "a.py"}` sem `conteudo`) → `422` com `detail` = lista de erros do pydantic sem URLs (`api.py:133-141`).

**Formato 2 — formulário** (`multipart/form-data` ou `application/x-www-form-urlencoded`):

| Campo do form | Tipo | Repetível |
| --- | --- | --- |
| `codigo` | texto | não |
| `nome` | texto | não |
| `arquivos` | arquivo (upload de `<input type="file" multiple>`) ou texto | **sim** |

- Em multipart, cada item de `arquivos` deve ser um upload (`UploadFile`); texto simples no campo → `400` ("o campo 'arquivos' deve conter arquivos, nao texto", `api.py:152-154`).
- O parser de formulário do Starlette é configurado com tetos ligeiramente acima dos limites da aplicação (`max_files=51`, `max_part_size=2 MB`) para que o erro `413` saia da aplicação com mensagem clara em vez de `400` genérico do parser (`api.py:144-149`).

### Regras de validação (aplicadas igualmente aos dois formatos — `montar_envios`, `api.py:98-120`)

| Regra | Limite | Erro |
| --- | --- | --- |
| Quantidade de arquivos por envio | ≤ 50 (`MAXIMO_DE_ARQUIVOS`) | `413` |
| Tamanho por arquivo (código colado inclusive) | ≤ 1.000.000 bytes (`TAMANHO_MAXIMO_POR_ARQUIVO`); em multipart lê-se 1 byte além do teto para detectar excesso sem baixar tudo | `413` |
| Nome do arquivo | reduzido ao **nome-base** — qualquer diretório (POSIX ou Windows) é descartado: `../../etc/app.py` → `app.py`, `C:\projeto\models.py` → `models.py` (neutraliza path traversal; `nome_seguro`, `api.py:75-91`) | — |
| Nome resultante | não pode ser vazio, `.` ou `..` | `400` |
| Extensão aceita | `.py` ou arquivo de configuração reconhecido por `configuracao.formato_de` (`.env`, YAML, JSON, INI, TOML, `.properties`) | `400` |
| Nomes duplicados no mesmo envio | proibidos (após redução ao nome-base) | `400` |
| Envio vazio | proibido | `400` |

Arquivo com **erro de sintaxe** não gera erro HTTP: é registrado em `varredura.falhas` na resposta `200` (`test_api.py:58-62`).

### Resposta `200 OK` — formato dos dados

Estrutura de `relatorio.para_dict()` (`relatorio.py:167-203`), com `raiz` fixa em `"envio"`:

```json
{
  "ferramenta": "owasp-scan",
  "versao": "0.2.0",
  "raiz": "envio",
  "momento": "2026-10-08T12:00:00",
  "varredura": {
    "arquivos_analisados": 2,
    "arquivos_de_configuracao": 1,
    "arquivos_com_falha": 0,
    "falhas": [
      {"arquivo": "quebrado.py", "motivo": "sintaxe", "mensagem": "invalid syntax", "linha": 3}
    ]
  },
  "resumo": {
    "total": 3,
    "rastreados_por_taint": 2,
    "candidatos_heuristicos": 1,
    "por_severidade": {"alta": 1, "media": 2},
    "por_owasp": {"A03:2021 Injection": 1},
    "por_cwe": {"CWE-89": 1},
    "por_arquivo": {"views.py": 2}
  },
  "achados": [
    {
      "arquivo": "views.py",
      "linha": 7,
      "cwe": "CWE-89",
      "owasp": "A03:2021 Injection",
      "vulnerabilidade": "SQL Injection",
      "severidade": "alta",
      "confianca": "alta",
      "trecho": "cursor.execute(\"SELECT ... \" + ident)",
      "descricao": "...",
      "recomendacao": "..."
    }
  ]
}
```

Notas do contrato:

- `achados[]` segue os **10 campos fixos** do contrato interno (`achado.py:116-127`), ordenados por severidade → confiança → arquivo → linha → CWE (`relatorio.ordenar`).
- `severidade` e `confianca` ∈ `{alta, media, baixa}`; `confianca == "baixa"` indica **candidato heurístico** (exige revisão manual — não afirma vulnerabilidade).
- Segredos detectados (CWE-798) chegam **mascarados** no `trecho` (`motor/credenciais.mascarar`).
- `varredura.arquivos_analisados` conta só `.py`; configuração entra em `arquivos_de_configuracao`.
- JSON e formulário produzem **resultados idênticos** (`test_api.py:153-156`).

### Códigos HTTP e possíveis erros

Todos os erros vêm como `{"detail": "..."}` (string nos erros da aplicação; lista de erros pydantic no `422` de esquema):

| Código | Quando | Exemplo de `detail` | Origem |
| --- | --- | --- | --- |
| `200` | análise concluída (mesmo com sintaxe inválida ou zero achados) | — | `analisar()` |
| `400` | envio vazio; nome inválido (vazio/`.`/`..`); extensão não suportada; nome duplicado; `arquivos` com texto em multipart | `"tipo de arquivo nao suportado: 'foto.png' (aceitos: .py e configuracao .env/.yaml/.json/.ini/.toml/.properties)"` | `montar_envios`/`nome_seguro` (`api.py:82-119`) |
| `413` | > 50 arquivos; arquivo > 1 MB | `"grande.py excede 1000000 bytes"` | `api.py:102-115` |
| `415` | `Content-Type` diferente de JSON/formulário | `"use Content-Type application/json ou multipart/form-data"` | `api.py:197-198` |
| `422` | JSON malformado ou fora do esquema pydantic | lista de `{loc, msg, type}` | `_envios_de_json` (`api.py:133-141`) |
| `405` | método não suportado na rota (ex.: `GET /analisar`) | padrão FastAPI | framework |

Erros internos não tratados retornariam `500` padrão do Starlette; o motor é resiliente a arquivo quebrado por construção (`FalhaDeLeitura`), então `500` não é esperado em uso normal. **[NECESSÁRIO CONFIRMAR]** comportamento sob condições extremas (ex.: JSON gigante — ver limitações).

### Exemplos de uso

**curl (JSON):**

```bash
curl -X POST http://127.0.0.1:8000/analisar \
  -H "Content-Type: application/json" \
  -d '{"codigo": "import sqlite3\nfrom flask import request\ndef v():\n    sqlite3.connect(\"x.db\").execute(\"SELECT * FROM t WHERE id=\" + request.args[\"id\"])\n"}'
```

**curl (upload multipart):**

```bash
curl -X POST http://127.0.0.1:8000/analisar \
  -F "arquivos=@app.py" -F "arquivos=@.env"
```

**JavaScript (formato previsto para o frontend — `TOOL/README.md` §API HTTP):**

```js
// código colado
const resultado = await (await fetch("http://127.0.0.1:8000/analisar", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ codigo: textarea.value }),
})).json();   // resultado.resumo, resultado.achados

// upload direto de <input type="file" multiple>
const form = new FormData();
for (const f of input.files) form.append("arquivos", f);
const resultado2 = await (await fetch("http://127.0.0.1:8000/analisar", {
  method: "POST", body: form,
})).json();
```

⚠️ O frontend do repositório (`frontend/src/App.jsx`) **ainda não faz nenhuma dessas chamadas** — a integração está prevista, não implementada.

---

## Aspectos transversais

### Middleware

Único middleware: `CORSMiddleware` (`api.py:67-72`).

| Configuração | Valor |
| --- | --- |
| `allow_origins` | `OWASPSCAN_ORIGENS` (env, separadas por vírgula; **padrão `*`**) |
| `allow_methods` | `["GET", "POST"]` (fixo no código — OPTIONS de preflight é tratado pelo próprio middleware) |
| `allow_headers` | `["*"]` |
| `allow_credentials` | não configurado (padrão FastAPI: `False`) |

Não há middleware de logging, autenticação, compressão ou tratamento de exceção customizado.

### Autenticação

**Nenhuma.** Não existe header de API key, token, sessão, OAuth ou qualquer verificação de identidade em nenhum endpoint. Consequência direta: a API só deve escutar em localhost (`OWASPSCAN_HOST` padrão `127.0.0.1`) ou atrás de proxy que aplique autenticação.

### Autorização

**Nenhuma** — sem autenticação, não há papéis/permissões. O único controle de acesso é o CORS (que protege o *navegador* de outras origens, não a API de clientes diretos como curl).

### Validação

Em camadas, toda em `api.py`:

1. **Esquema** — modelos pydantic `Envio`/`ArquivoEnviado` no formato JSON (`422` se violado);
2. **Content-Type** — dispatch explícito (`415`);
3. **Aplicação** — `montar_envios()`: quantidade, tamanho, nome-base, extensão, duplicatas, vazio (`400`/`413`);
4. **Parser do Starlette** — tetos `max_files=51`/`max_part_size=2MB` como rede de proteção do multipart;
5. **Motor** — sintaxe inválida não é erro HTTP: vira `falhas[]` na resposta `200`.

### Tratamento de erros

`HTTPException` com `detail` em português para todos os erros de entrada; `ValidationError` do pydantic é capturada e reemitida como `422` com `errors(include_url=False)` (sem URLs internas do pydantic, `api.py:136-138`). Sem handler global customizado (`@app.exception_handler`) — erros inesperados seguem o padrão `500` do Starlette.

### Rate limiting

**Nenhum.** Não há limite de requisições por cliente nem de concorrência (além do teto de 50 arquivos/1 MB por envio). A análise é CPU-bound e roda em threadpool — requisições simultâneas ilimitadas competem por CPU. Risco registrado em `docs/arquitetura.md` §Segurança.

### Uploads

- Aceitos via `multipart/form-data` (campo repetível `arquivos`) ou como texto em JSON (`arquivos[].conteudo`).
- Tipos aceitos: `.py` e configuração (`.env`, `.yaml`/`.yml`, `.json`, `.ini`, `.toml`, `.properties` — definição em `configuracao.formato_de`).
- Nomes reduzidos ao nome-base (anti path traversal, testado com `../../`, caminhos absolutos POSIX e Windows).
- Gravados em `TemporaryDirectory` destruída ao final de cada requisição — **nenhum upload é armazenado**.
- Binários reais não são suportados: o conteúdo é tratado como texto (JSON exige string; multipart aceita bytes mas o motor parseia texto). Arquivo não-texto com extensão válida seria registrado como falha de leitura/codificação na resposta `200`. **[NECESSÁRIO CONFIRMAR]** comportamento detalhado para binários grandes com extensão `.py`.

### Paginação, filtros e ordenação

**Não existem.** A resposta devolve todos os achados de uma vez, sem parâmetros de página/limite/filtro. A ordenação é fixa de servidor: severidade → confiança → arquivo → linha → CWE (`relatorio.ordenar`, `relatorio.py:26-27,50-61`) — não configurável pelo cliente.

### Banco de dados

**Nenhum endpoint acessa banco de dados.** O projeto inteiro não tem persistência (ver `docs/arquitetura.md` §Dados e armazenamento).

### CORS em desenvolvimento

Padrão `*` permite que o frontend Vite (`http://localhost:5173`) chame a API sem configuração. Para restringir: `OWASPSCAN_ORIGENS=http://localhost:5173` (detalhes em `docs/configuracao.md` §1).

---

## Cadeia interna de processamento (`POST /analisar`)

```
analisar(request)                                   api.py:191
  ├─ dispatch por Content-Type                      api.py:192-198
  │    ├─ _envios_de_json(request)                  api.py:133  → pydantic Envio
  │    └─ _envios_de_formulario(request)            api.py:144  → request.form(tetos)
  ├─ montar_envios(codigo, nome, arquivos)          api.py:98   → {nome_seguro: bytes}
  │    └─ nome_seguro(nome)                         api.py:75   → nome-base validado
  └─ run_in_threadpool(varrer, envios)              api.py:200  (CPU-bound fora do event loop)
       varrer(envios)                                api.py:123
         ├─ tempfile.TemporaryDirectory("owaspscan-")
         ├─ grava bytes dos arquivos
         ├─ varredura.executar(raiz)                 varredura.py:92
         │    ├─ analisador.analisar_diretorio()     → ArquivoAnalisado/FalhaDeLeitura
         │    ├─ motor.taint.analisar_taint()        → Escopos
         │    ├─ 15× detectores.detectar()           → Achados
         │    └─ configuracao.ler_diretorio() + DetectorCredenciaisEmConfiguracao
         ├─ pasta temporária destruída (with)
         └─ relatorio.para_dict(replace(raiz="envio")) → JSON da resposta
```

## Limitações conhecidas da API

1. **Sem autenticação, autorização nem rate limiting** — inadequada para exposição pública direta.
2. **Corpo JSON sem limite de tamanho prévio** — o limite de 1 MB por arquivo é aplicado *depois* de `await request.json()` carregar o corpo inteiro em memória (`api.py:135`); um cliente malicioso pode enviar JSON muito grande. O multipart tem proteção (tetos do Starlette), o JSON não.
3. **Sem timeout de análise** — código patologicamente complexo roda até terminar (ponto fixo do taint por escopo).
4. **Sem fila/concorrência controlada** — cada requisição ocupa uma thread do pool padrão do Starlette.
5. **Um único processo** — sem configuração de workers múltiplos (`uvicorn.run(app)` sem parâmetros de workers).
6. **Frontend ainda não integrado** — a API foi construída "para o site" (Fases 18-19 do git), mas `frontend/` não a chama.

## Referências

- Implementação: `TOOL/owaspscan/api.py`
- Testes (comportamentos aqui documentados): `TOOL/tests/test_api.py`
- Guia de uso resumido: `TOOL/README.md` §"API HTTP (para o site)"
- Contrato do achado (campos da resposta): `TOOL/owaspscan/achado.py`
- Estrutura do JSON: `TOOL/owaspscan/relatorio.py` (`para_dict`)
- Variáveis de ambiente: `docs/configuracao.md` §1
- Contexto de arquitetura: `docs/arquitetura.md`
