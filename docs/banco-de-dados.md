# Banco de dados / Camada de persistência

Análise completa da camada de persistência do projeto AEGIS, baseada exclusivamente no código. Verificação feita por varredura de todo o código-fonte (`TOOL/owaspscan/`, `frontend/src/`) por drivers, ORMs e APIs de armazenamento.

## Conclusão central

**O projeto não possui banco de dados nem camada de persistência.** Nenhuma informação é armazenada entre execuções: a CLI analisa arquivos do disco do usuário e imprime o resultado no terminal; a API grava cada envio numa pasta temporária destruída ao final da própria requisição. O frontend guarda apenas a preferência de tema no `localStorage` do navegador do usuário.

Evidências da ausência:

| Verificação | Resultado |
| --- | --- |
| Drivers/ORMs no código (`sqlalchemy`, `sqlite3`, `psycopg`, `pymongo`, `redis`, `mysql`, `pickle`, `shelve`, `dbm`) | **zero imports** em `TOOL/owaspscan/` — todas as ocorrências dessas palavras no pacote são texto de descrição de detectores ou entradas do catálogo de sinks (código que a ferramenta *analisa*, não que ela *usa*) |
| `TOOL/pyproject.toml` | `dependencies = []` no núcleo; extras `api` (fastapi/uvicorn/python-multipart) e `dev` (pytest/httpx) — nenhum pacote de banco |
| Migrations | não existem (sem Alembic, Django migrations, Flask-Migrate, Knex, Prisma etc.) |
| Seeds | não existem |
| Schemas/DDL (`.sql`, modelos, entidades persistentes) | não existem |
| Repositories / DAOs / services de banco | não existem |
| Conexões, connection strings, env vars de banco | não existem (as únicas env vars do projeto são `OWASPSCAN_HOST/PORTA/ORIGENS`, de rede — `api.py:46,223-224`) |
| Frontend (`indexedDB`, `sessionStorage`, Supabase, Firebase) | inexistentes; único armazenamento: `localStorage` |

⚠️ Observação importante: `sqlite3`, `psycopg2`, ORM `create()`/`save()`, `filter_by(...)` etc. aparecem com frequência no repositório — mas **somente** em `TOOL/owaspscan/motor/catalogo.py` (definições de *sinks* que o motor procura em código de terceiros) e em `TOOL/tests/amostras/` (corpus de código vulnerável/seguro usado como fixture). Nada disso é persistência do próprio projeto.

## Fluxo de dados vs. fluxo clássico com banco

O fluxo pedido (`Aplicação → camada de acesso → banco de dados`) **não existe** neste projeto. O fluxo real é:

```
Aplicação (CLI ou API)
  ↓
varredura.executar()          ← orquestração em memória (varredura.py:92)
  ↓
leitura de arquivos           ← disco do usuário (CLI) ou TemporaryDirectory (API)
  ↓
análise AST + detectores      ← 100% em memória
  ↓
relatorio (texto / JSON)      ← stdout (CLI) ou resposta HTTP (API)
  ↓
FIM — nada é gravado          ← a pasta temporária da API é destruída (api.py:125-130)
```

Não há camada de acesso a dados: entre a aplicação e "o fim" existem apenas estruturas de dados imutáveis em memória (`Achado`, `Varredura` — dataclasses frozen).

## O único armazenamento existente (efêmero e local)

### 1. Pasta temporária da API — `TOOL/owaspscan/api.py:123-130`

| Aspecto | Detalhe |
| --- | --- |
| O que é | `tempfile.TemporaryDirectory(prefix="owaspscan-")` criado dentro de `varrer()` |
| Ciclo de vida | **criação**: a cada `POST /analisar`; **leitura**: `executar()` lê os bytes gravados; **atualização**: não ocorre (arquivos são gravados uma vez); **exclusão**: automática ao sair do bloco `with` — antes da resposta HTTP terminar de ser montada |
| Conteúdo | os arquivos enviados pelo cliente, com nomes reduzidos ao nome-base (anti path traversal, `nome_seguro`) |
| Persistência residual | nenhuma — nem sucesso nem falha deixam rastro em disco; a resposta substitui o caminho real por `raiz="envio"` para não vazar o caminho do servidor (testado em `test_api.py:53-56`) |
| Privacidade | código do usuário nunca é retido — coerente com o texto de privacidade exibido no frontend |

### 2. `localStorage` do navegador — `frontend/src/App.jsx:33,61`

| Aspecto | Detalhe |
| --- | --- |
| Chave | `aegis-tema` |
| Valores possíveis | `'dark'` (padrão) ou `'light'` |
| Ciclo de vida | **criação/leitura**: inicialização do `useState` do tema; **atualização**: a cada alternância de tema (`useEffect`); **exclusão**: nunca (persiste até o usuário limpar o navegador) |
| Escopo | navegador do usuário; nenhum dado sai do cliente |

### 3. Arquivos do usuário analisados pela CLI

A CLI **lê** o caminho informado e nunca escreve nele. A única saída opcional em disco seria redirecionamento feito pelo próprio usuário (ex.: `--json > relatorio.json` — padrão que o `.gitignore` do `TOOL/` já prevê excluir).

## Entidades de dados (em memória, não persistentes)

Para completude do mapeamento: as "entidades" do sistema são dataclasses que nascem e morrem dentro de uma execução. Campos confirmados no código — nada aqui é tabela ou documento de banco.

### `Achado` — `TOOL/owaspscan/achado.py:134-177` (frozen dataclass)

Um achado de vulnerabilidade. É a entidade central do contrato interno.

| Campo | Tipo | Finalidade |
| --- | --- | --- |
| `arquivo` | `str` | caminho relativo à raiz analisada (na API: nome-base enviado; raiz exibida `"envio"`) |
| `linha` | `int` (≥1, validado) | linha do sink no arquivo |
| `cwe` | `str` | ex. `"CWE-89"` — chave de `MAPA_CWE_OWASP` (16 CWEs) |
| `owasp` | `str` | derivado do mapa (ex. `"A03:2021 Injection"`) — o construtor **impede** valor divergente |
| `vulnerabilidade` | `str` | derivado do mapa (ex. `"SQL Injection"`) |
| `severidade` | `Literal["alta","media","baixa"]` | gravidade; `alta` define o exit code 1 da CLI |
| `confianca` | `Literal["alta","media","baixa"]` | qualidade da cadeia fonte→sink; `baixa` = candidato heurístico |
| `trecho` | `str` | código-fonte do achado (≤120 chars; segredos mascarados) |
| `descricao` | `str` | explicação educativa |
| `recomendacao` | `str` | exemplo/orientação de correção |

"Chaves"/integridade: não há ID nem chave primária; a identidade de um achado é o conjunto `(arquivo, linha, cwe)` — base da ordenação estável (`detectores/base.py:28-30`). "Constraints" equivalentes: validação do `__post_init__` (CWE conhecida, owasp/vulnerabilidade coerentes com o mapa, enums válidos, linha ≥1) sob pena de `ClassificacaoInvalida`.

### `Varredura` — `TOOL/owaspscan/varredura.py:65-89` (frozen dataclass)

Resultado agregado de uma execução — o "objeto de sessão" que a API serializa e a CLI formata.

| Campo | Tipo | Finalidade |
| --- | --- | --- |
| `raiz` | `str` | caminho analisado (API: `"envio"`) |
| `achados` | `tuple[Achado, ...]` | todos os achados ordenados |
| `arquivos_analisados` | `int` | `.py` parseados com sucesso |
| `arquivos_de_configuracao` | `int` | configs lidas |
| `falhas` | `tuple[FalhaDeLeitura, ...]` | arquivos não analisáveis (sintaxe/codificação/IO) |
| `momento` | `datetime` | timestamp da execução |
| `versao` | `str` | `"0.2.0"` |

Derivados (properties, sem armazenamento): `confirmados` (confiança ≠ baixa), `candidatos` (confiança = baixa), `tem_severidade_alta`.

### `FalhaDeLeitura` — `TOOL/owaspscan/analisador.py:38-45`

| Campo | Tipo | Finalidade |
| --- | --- | --- |
| `arquivo` | `str` | caminho de exibição |
| `motivo` | `str` | `"sintaxe"`, `"codificacao"` ou `"io"` |
| `mensagem` | `str` | detalhe do erro |
| `linha` | `int \| None` | linha do erro de sintaxe, quando houver |

### Secundárias (não serializadas na saída)

`ArquivoAnalisado` (`analisador.py:48-59`: arquivo, caminho, fonte, árvore AST), `Escopo`/`Procedencia` (`motor/taint.py`: estado da análise de contaminação), `ArquivoDeConfiguracao`/`EntradaDeConfiguracao` (`configuracao.py:48-68`: linha, chave, valor, formato), `Resumo` (`relatorio.py:30-41`: contagens agregadas). Todas vivem apenas durante uma execução.

## CRUD — onde ocorre cada operação

Não há CRUD sobre dados persistentes. Mapeando as operações sobre o único armazenamento real (pasta temporária da API) e o `localStorage`:

| Operação | Pasta temporária da API (`api.py`) | `localStorage` (`App.jsx`) |
| --- | --- | --- |
| **Criação** | `varrer()`: `TemporaryDirectory(...)` + `write_bytes` por arquivo (`api.py:125-128`) | `setItem('aegis-tema', ...)` no `useEffect` (`:61`) |
| **Leitura** | `executar()` → `analisar_diretorio()` lê os `.py`; `ler_diretorio()` lê configs | `getItem('aegis-tema')` na inicialização do estado (`:33`) |
| **Atualização** | não ocorre — arquivos são imutáveis após gravados | a cada alternância de tema |
| **Exclusão** | automática na saída do `with` (`api.py:125`) — por requisição | nunca (fica com o usuário) |

## Consultas (queries) importantes

**Nenhuma query SQL é executada pelo projeto.** As strings SQL que existem no repositório são:

1. **Sinks declarados** em `motor/catalogo.py` (`SinkSql`: `execute`, `executemany`, `executescript`, `raw`, `extra`, `execute_batch`, `execute_values`... cobrindo DB-API 2.0/PEP 249, Django e SQLAlchemy) — padrões que o detector de CWE-89 *procura no código analisado*;
2. **Fixtures** em `tests/amostras/` (ex.: `flask_sqli.py` com `sqlite3.connect("x.db").execute("SELECT ... " + ident)`) — código de exemplo intencionalmente vulnerável, nunca executado pela ferramenta (o motor só parseia AST).

A "consulta" mais próxima de uma query no sistema é `literais_de_string()` (`motor/taint.py:390-414`), que resolve constantes de uma expressão AST para inspecionar o texto de queries *do código de terceiros* — novamente, análise, não execução.

## Implicações da ausência de banco

1. **Stateless por design**: cada execução (CLI ou requisição HTTP) é independente; não há histórico de análises, contas de usuário, relatórios salvos nem compartilhamento com comunidade — embora textos estáticos do frontend (`App.jsx:280-288`, FAQ/privacidade) mencionem "histórico de auditorias para usuários autenticados" e "colaboração via hashes", funcionalidades que **não existem** em nenhuma camada (inconsistência já registrada em `docs/arquitetura.md` §Riscos).
2. **Escala horizontal trivial**: sem estado, qualquer instância da API atende qualquer requisição; o custo é só CPU.
3. **Privacidade forte**: código enviado nunca é retido — argumento central do texto de privacidade do produto.
4. **Se persistência vier a ser necessária** (ex.: histórico de análises do site), será uma decisão nova de arquitetura: candidata natural a ADR em `docs/decisoes/` (pasta hoje só com template). Nada no código atual antecipa essa escolha.

## Referências

- `TOOL/owaspscan/api.py` (`varrer`, `nome_seguro`, ciclo do tempdir)
- `TOOL/owaspscan/achado.py`, `varredura.py`, `analisador.py`, `relatorio.py` (entidades em memória)
- `TOOL/owaspscan/motor/catalogo.py` (sinks SQL — análise, não uso)
- `TOOL/tests/test_api.py:53-62` (não vazamento de caminho, falha de sintaxe como dado)
- `frontend/src/App.jsx:33,61` (localStorage)
- `docs/arquitetura.md` §Dados e armazenamento · `docs/configuracao.md` §Ausências confirmadas
