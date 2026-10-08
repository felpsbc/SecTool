# Configuração

Todas as configurações utilizadas pelo projeto AEGIS, com finalidade, obrigatoriedade, exemplos seguros e impacto em caso de erro. Inventário confirmado por varredura do repositório (commit `a90120a`): nenhum arquivo de configuração foi omitido, e nenhuma credencial real é exposta neste documento.

## Visão geral

| O que se configura | Onde | Mecanismo |
| --- | --- | --- |
| API HTTP (host, porta, CORS) | `TOOL/owaspscan/api.py` | variáveis de ambiente (todas opcionais) |
| Limites de upload da API | `TOOL/owaspscan/api.py:40-41` | constantes no código (hardcoded) |
| Pacote Python, extras e pytest | `TOOL/pyproject.toml` | TOML de empacotamento |
| Build/dev/lint do frontend | `frontend/package.json`, `vite.config.js` | npm scripts + config do Vite |
| Estilo do frontend | `frontend/tailwind.config.js`, `postcss.config.js` | Tailwind/PostCSS |
| Lint do frontend | `frontend/.oxlintrc.json` | Oxlint |
| Shell HTML, favicon, cor da aba | `frontend/index.html` | HTML estático |
| Estilo de editor | `.editorconfig` (raiz) | EditorConfig |
| Lint de Markdown | `.markdownlint.json` (raiz) | markdownlint |
| Arquivos ignorados pelo Git | `.gitignore` (raiz, `TOOL/`, `frontend/`) | git |
| Templates de issue/PR | `.github/ISSUE_TEMPLATE/*.yml`, `.github/PULL_REQUEST_TEMPLATE.md` | GitHub |

**Não existem** no projeto: `.env` real, configuração de banco de dados (não há banco), configuração de autenticação (a API não tem autenticação), configuração de serviços externos (não há), configuração de produção/deploy (não há Docker nem CI). Detalhes nas seções [Ausências confirmadas](#ausências-confirmadas) e [Fixtures de teste](#fixtures-de-teste-não-são-configurações-do-projeto).

## 1. Variáveis de ambiente da API HTTP

Únicas variáveis de ambiente do projeto. São lidas em `TOOL/owaspscan/api.py` (linhas 46 e 223-224), aplicam-se **somente** ao servidor da API (`python -m owaspscan.api`) e **todas são opcionais** — o projeto funciona sem definir nenhuma.

Não existe arquivo `.env` carregado automaticamente; as variáveis devem estar no ambiente do processo (export, prefixo no comando ou configuração do supervisor de processo).

### `OWASPSCAN_HOST`

| | |
| --- | --- |
| Finalidade | endereço em que o Uvicorn escuta |
| Onde é utilizada | `api.py:223` (`main()` → `uvicorn.run(host=...)`) |
| Obrigatória | não — padrão `127.0.0.1` (somente conexões locais) |
| Exemplo seguro | `OWASPSCAN_HOST=127.0.0.1` (desenvolvimento local) |
| Impacto se incorreta | valor inválido → Uvicorn falha ao subir. ⚠️ Definir `0.0.0.0` expõe a API na rede **sem nenhuma autenticação** — só fazer isso atrás de proxy/reverse proxy que aplique auth e rate limit |

### `OWASPSCAN_PORTA`

| | |
| --- | --- |
| Finalidade | porta TCP do servidor |
| Onde é utilizada | `api.py:224` (`main()` → `uvicorn.run(port=...)`) |
| Obrigatória | não — padrão `8000` |
| Exemplo seguro | `OWASPSCAN_PORTA=9000 .venv/bin/python -m owaspscan.api` |
| Impacto se incorreta | valor não numérico → `ValueError` no `int()`; porta ocupada → erro `address already in use` na subida |

### `OWASPSCAN_ORIGENS`

| | |
| --- | --- |
| Finalidade | origens permitidas no CORS, separadas por vírgula |
| Onde é utilizada | `api.py:46` → `CORSMiddleware(allow_origins=ORIGENS)` (`api.py:67-72`) |
| Obrigatória | não — padrão `*` (qualquer origem) |
| Exemplo seguro | dev local com o frontend do projeto: `OWASPSCAN_ORIGENS=http://localhost:5173` · produção: `OWASPSCAN_ORIGENS=https://app.exemplo.org` |
| Impacto se incorreta | origem do site ausente da lista → navegador **bloqueia** a resposta da API (erro de CORS no console; a requisição chega a ser processada). Manter `*` fora do desenvolvimento → qualquer website pode chamar a API em nome de usuários da rede. Obs.: `allow_methods` é fixo em `GET, POST` |

Exemplo completo (desenvolvimento local, valores explícitos):

```bash
OWASPSCAN_HOST=127.0.0.1 \
OWASPSCAN_PORTA=8000 \
OWASPSCAN_ORIGENS=http://localhost:5173 \
.venv/bin/python -m owaspscan.api
```

Nenhuma outra parte do projeto lê variáveis de ambiente: o núcleo/CLI é 100% offline e o frontend não usa nenhuma `VITE_*`.

## 2. Limites hardcoded da API

Valores fixos no código, sem variável de ambiente. Para alterá-los é preciso editar `TOOL/owaspscan/api.py` (e os testes correspondentes em `TOOL/tests/test_api.py`, que importam as constantes).

| Constante | Valor | Onde | Finalidade / impacto |
| --- | --- | --- | --- |
| `MAXIMO_DE_ARQUIVOS` | 50 | `api.py:40` | teto de arquivos por envio; exceder → HTTP 413. Muito baixo frustra análises de projetos; muito alto amplia custo de CPU por requisição |
| `TAMANHO_MAXIMO_POR_ARQUIVO` | 1.000.000 bytes | `api.py:41` | teto por arquivo; exceder → HTTP 413. Mesmo teto usado pelo leitor de configuração (`configuracao.py`) |
| `NOME_DO_CODIGO_COLADO` | `"codigo.py"` | `api.py:42` | nome exibido quando o código vem colado no campo `codigo` |
| `RAIZ_EXIBIDA` | `"envio"` | `api.py:43` | substitui o caminho temporário na resposta (não vaza caminhos do servidor) |
| `LIMITE_TRECHO` | 120 chars | `analisador.py:35` | truncamento do trecho de código exibido no achado |
| `LARGURA` | 74 cols | `relatorio.py:25` | largura do relatório de texto |

## 3. `TOOL/pyproject.toml` — pacote, extras e pytest

Obrigatório para instalar o TOOL (`pip install -e .`); nunca precisa ser editado para usar a ferramenta.

| Seção | Conteúdo | Impacto se incorreta/ausente |
| --- | --- | --- |
| `[project]` | `name = "owaspscan"`, `version = "0.2.0"`, `requires-python = ">=3.11"`, `dependencies = []` | remover `requires-python` permitiria instalar em Python <3.11, onde o código falha (`match/case`). Adicionar `dependencies` violaria o princípio "núcleo stdlib-only" (`CLAUDE.md`) |
| `[project.optional-dependencies]` | `api = [fastapi>=0.110, uvicorn>=0.29, python-multipart>=0.0.9]` · `dev = [pytest>=8.0, httpx>=0.27]` | instalar sem `[api]` → `ModuleNotFoundError: fastapi` ao rodar `python -m owaspscan.api`; sem `[dev]` → pytest/httpx ausentes |
| `[build-system]` | `setuptools>=68` | setuptools antigo → falha no build do wheel |
| `[tool.setuptools.packages.find]` | `include = ["owaspscan*"]` | sem isso, subpacotes (`motor/`, `detectores/`) poderiam ficar fora da instalação |
| `[tool.pytest.ini_options]` | `testpaths = ["tests"]`, `python_files = ["test_*.py"]`, `addopts = "-q"` | sem `testpaths`, pytest varreria `tests/amostras/` (código propositalmente vulnerável) e o corpus não segue `test_*.py`; sem `-q`, saída mais verbosa |

Nota: a versão `0.2.0` é duplicada em `varredura.py:40` (`VERSAO`) — as duas precisam ser atualizadas juntas (o `pyproject` vale para o pacote; `VERSAO` aparece no relatório e no `/saude`).

## 4. Frontend — build e desenvolvimento

### `frontend/package.json`

- **Finalidade**: dependências e scripts npm.
- **Obrigatório**: sim, para qualquer comando npm.
- **Scripts**: `dev` (vite), `build` (vite build), `lint` (oxlint), `preview` (vite preview).
- **Impacto**: editar versões aqui sem regenerar o `package-lock.json` causa divergência — o lockfile (v3) congela as resoluções; `npm install` segue o lock.

### `frontend/vite.config.js`

- **Finalidade**: configuração do build/dev server.
- **Conteúdo atual**: apenas `plugins: [react()]` — **nenhuma outra configuração**.
- **Obrigatório**: sim para o plugin React (JSX).
- **Impacto / lacunas**: sem `server.port` (Vite usa o padrão 5173), sem `server.proxy` e sem `define`/env — quando o frontend for integrado à API, será preciso configurar proxy de dev ou URL de API via `VITE_*`. Hoje não há nada a configurar aqui.

### `frontend/tailwind.config.js`

- **Finalidade**: Tailwind CSS 3.
- **Configurações**: `darkMode: 'class'` — **essencial**: o tema claro/escuro do `App.jsx` funciona adicionando/removendo a classe `dark` em `<html>` (`App.jsx:47-62`); `content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"]`.
- **Impacto se incorreta**: mudar `darkMode` para `'media'` quebra o botão de alternância de tema; remover caminhos de `content` faz o purge eliminar classes usadas → estilos somem no build de produção.

### `frontend/postcss.config.js`

- **Finalidade**: pipeline CSS (`tailwindcss` + `autoprefixer`).
- **Impacto**: sem ele, o `index.css` (diretivas `@tailwind`) não compila — site sem estilo.

### `frontend/.oxlintrc.json`

- **Finalidade**: lint do frontend (`npm run lint`).
- **Configurações**: plugins `react` e `oxc`; `react/rules-of-hooks: error` (violação de hooks quebra o build de qualidade), `react/only-export-components: warn` com `allowConstantExport`.
- **Impacto**: afrouxar `rules-of-hooks` para `warn/off` permite bugs reais de estado no React.

### `frontend/index.html`

- **Finalidade**: shell da SPA — contém configurações embutidas: favicon SVG inline (letra "A", azul no claro/verde no escuro via `prefers-color-scheme`), `<meta name="theme-color" id="meta-theme-color">` (manipulado em runtime pelo `App.jsx:49-59`), `lang="pt"`, título "AEGIS | Motor de Análise Estática".
- **Impacto**: remover o `id="meta-theme-color"` desativa a atualização da cor da aba ao alternar tema (o código verifica a existência antes de usar).

## 5. Qualidade e estilo (raiz)

### `.editorconfig`

- **Finalidade**: padronizar editores — `charset = utf-8`, `end_of_line = lf`, `insert_final_newline`, `trim_trailing_whitespace`, `indent_style = space`; Markdown não sofre trim de espaços à direita (necessário para quebras de linha); YAML com indentação 2.
- **Obrigatório**: não (convencional). **Impacto**: sem ele, diffs ruidosos e lint de Markdown/YAML inconsistente entre colaboradores.

### `.markdownlint.json`

- **Finalidade**: regras do markdownlint para a documentação — `default: true` com `MD013: false` (sem limite de linha), `MD033: false` (HTML inline permitido), `MD024: siblings_only` (títulos repetidos permitidos fora do mesmo nível).
- **Obrigatório**: não há executor configurado no repositório (sem CI) — a configuração existe para quem roda markdownlint localmente. **Impacto**: alterar regras muda o que é aceito nos documentos de `docs/`.

### `.gitignore` (raiz, `TOOL/`, `frontend/`)

Configuração relevante de segurança e higiene:

| Rega | Onde | Finalidade / impacto |
| --- | --- | --- |
| `.env`, `.env.*`, `!.env.example` | raiz | impede commit de segredos locais; permite modelos. Se removida, risco direto de vazamento (política em `SECURITY.md`) |
| `*.key`, `*.pem`, `*.p12`, `*.pfx` | raiz | idem, para certificados/chaves |
| `.venv/`, `__pycache__/`, `.pytest_cache/`, `*.egg-info/` | raiz + `TOOL/` | ambiente e caches fora do histórico |
| `relatorio.json` | `TOOL/` | saída de análise local não vai para o repositório |
| `node_modules`, `dist`, `*.local` | raiz + `frontend/` | dependências e build do frontend |

## 6. Configuração do GitHub (`.github/`)

- **Finalidade**: padronização de contribuições — formulários de issue (`bug.yml`, `requisito.yml`, `documentacao.yml`, `pesquisa.yml`) e templates de PR.
- **`ISSUE_TEMPLATE/config.yml`**: `blank_issues_enabled: false` (força usar os formulários) + `contact_links` apontando para `https://github.com/Campus-CEUB` com texto "Leia o guia dos alunos (docs/guia-alunos.md)".
- **Obrigatório**: não (afeta apenas o fluxo no GitHub).
- **Impacto / inconsistência**: o contact link é genérico da organização (o próprio texto pede para substituir pelo link da turma); `blank_issues_enabled: false` bloqueia issues livres — se os formulários tiverem erro de sintaxe YAML, o GitHub desabilita o formulário afetado.
- **Ausente**: `.github/workflows/` — não há nenhuma configuração de CI/CD.

## Ausências confirmadas

Varredura por `.env*`, `*.yml`, `*.yaml`, `*.toml`, `*.ini`, `*.cfg`, `*.json`, `*.properties` fora de `tests/amostras` e `node_modules` retornou apenas os arquivos já fichados acima. Portanto:

| Categoria | Situação |
| --- | --- |
| Banco de dados | **não se aplica** — o projeto não tem banco; a API usa pasta temporária efêmera por requisição (`api.py:125`) |
| Autenticação/autorização da API | **não existe configuração** — a API é aberta; o único controle é o CORS (`OWASPSCAN_ORIGENS`) |
| Serviços externos | **nenhum** — nenhuma config de terceiros (e-mails, S3, provedores de IA etc.) |
| Produção/deploy | **nenhuma** — sem Dockerfile, docker-compose de deploy, nginx, systemd, IaC ou CI |
| `.env` / `.env.example` do projeto | **não existem** (ver fixtures abaixo); se a equipe criar um para a API, seguir o modelo da seção 1 |
| Configuração de dev vs prod do frontend | **não separadas** — sem `.env.development`/`.env.production`, sem URLs de API por ambiente |

## Fixtures de teste NÃO são configurações do projeto

Os arquivos de configuração em `TOOL/tests/amostras/*/config/` (`.env`, `.env.example`, `producao.env`, `docker-compose.yml`, `settings.json`, `servicos.ini`, `application.properties`, `pyproject.toml`) são **amostras propositalmente vulneráveis/seguras** usadas como corpus do detector de credenciais (CWE-798) e pelos testes. Contêm segredos fictícios de exemplo. Não ler como configuração do projeto, não editar para configurar nada e não copiar seus valores.

## Recomendações (não implementadas)

1. **Exemplo de `.env` seguro para a API** — criar `TOOL/.env.example` (sem segredos, coberto pela regra `!.env.example` do `.gitignore`):

   ```bash
   # Configuração local da API owaspscan (copie para o ambiente do processo;
   # nenhuma destas variáveis é obrigatória — valores entre parênteses são os padrões)
   OWASPSCAN_HOST=127.0.0.1        # (127.0.0.1) não expor em 0.0.0.0 sem proxy com auth
   OWASPSCAN_PORTA=8000            # (8000)
   OWASPSCAN_ORIGENS=http://localhost:5173   # (*) restrinja às origens reais do site
   ```

2. **Restringir CORS fora de desenvolvimento** — o padrão `*` só é aceitável em localhost; definir `OWASPSCAN_ORIGENS` explicitamente em qualquer ambiente compartilhado.
3. **Configurar a integração frontend↔API por ambiente** — quando o frontend passar a consumir `POST /analisar`, usar variável `VITE_API_URL` + `server.proxy` no `vite.config.js` para desenvolvimento, evitando hardcode de `http://127.0.0.1:8000`.
4. **Sincronizar versões** — `pyproject.toml` (`version`) e `varredura.py` (`VERSAO`) duplicam "0.2.0"; considerar fonte única.
5. **Corrigir o contact link** de `.github/ISSUE_TEMPLATE/config.yml` para o repositório/guia real da turma.

## Referências

- Arquitetura e decisões: `docs/arquitetura.md`
- Instalação passo a passo: `docs/INSTALACAO.md`
- Contrato e exemplos da API: `TOOL/README.md` §"API HTTP (para o site)"
- Política de segredos: `SECURITY.md`
