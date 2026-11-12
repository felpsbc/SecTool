# Deploy — AEGIS / OWASP-Scan

Guia de execução do projeto em um ambiente de produção. Todas as afirmações
deste documento foram verificadas no código do repositório (`TOOL/owaspscan/`,
`frontend/`, `TOOL/pyproject.toml`, `frontend/package.json`) e na documentação
oficial da Vercel. Etapas que dependem de decisões de infraestrutura que o
repositório não registra estão marcadas com **[NECESSÁRIO CONFIRMAR]**.

## Escopo e estado atual

O projeto tem duas partes independentes, com ciclos de vida independentes:

| Parte | Diretório | Artefato | Onde roda em produção |
| --- | --- | --- | --- |
| Site (interface) | `frontend/` | `dist/` estático | **Vercel** (CDN + HTTPS automático) |
| API HTTP (motor exposto) | `TOOL/` | servidor Uvicorn | Host próprio **[NECESSÁRIO CONFIRMAR]** |
| Motor / CLI | `TOOL/` | pacote `owaspscan` | Onde o usuário o instalar (pip) |

### O repositório não contém infraestrutura de deploy

Verificado na árvore do repositório **e** em todo o histórico do Git
(`git log --all --diff-filter=D --name-only`): não existe `Dockerfile`,
`docker-compose.yml` de deploy, `.dockerignore`, `nginx.conf`, unidade
`systemd`, `Procfile`, `Makefile`, `vercel.json` ou `.github/workflows/`.

Os únicos `docker-compose.yml` do repositório estão em
`TOOL/tests/amostras/{seguro,vulneravel}/config/` e são **fixtures** de teste
do detector de credenciais (CWE-798) — contêm credenciais fictícias e não
configuram nada.

Consequência: os arquivos de configuração citados neste documento são
**propostas a criar** nos servidores, não arquivos já versionados.

### O site publicado é uma demonstração do produto, não um cliente da API

Esta é a diferença mais importante entre o repositório e a descrição usual
dele, e precisa ser dita com clareza antes de qualquer passo de deploy.

- O site em `frontend/` **não chama a API**. Em `HEAD`, `frontend/src/App.jsx`
  faz a análise no próprio navegador, com regras de expressão regular
  definidas no array `REGRAS_SAST` (`App.jsx:32`) e na função `analisarTexto`
  (`App.jsx:113`), dentro de um `setTimeout` de 1,2 s (`App.jsx:137`) que
  simula o tempo de processamento.
- `frontend/src/api.js` (51 linhas) e `frontend/src/Resultado.jsx` (89 linhas)
  **existem no repositório mas estão órfãos**: `main.jsx` importa apenas
  `./App.jsx`, e `App.jsx` importa apenas `./translate`. Nenhum `import`
  alcança `api.js` ou `Resultado.jsx`. Ambos foram introduzidos no commit
  `79ab534` ("Fase 20: site ligado a API") e ficaram sem uso quando `App.jsx`
  foi reescrito no commit `cb9152e`.
- Consequências diretas:
  - `VITE_API_URL` e o proxy `/api` do `vite.config.js` **estão inertes** no
    build atual. Definir `VITE_API_URL` na Vercel não muda o comportamento do
    site.
  - A publicação na Vercel **não depende do backend**. A API pode estar fora
    do ar sem impacto no site.
  - O roteiro de demonstração (`docs/teste/ROTEIRO_DE_DEMONSTRACAO.md`) usa o
    `aegis.py`, o notebook Colab e a API — não o site, cujas abas não retornam
    achados do motor.
- O valor do site é demonstrativo: ele apresenta o produto, sua interface e
  suas telas. O produto em si é o motor `owaspscan`, distribuído via pip e
  exposto pela API.

O [Apêndice D](#apêndice-d--conectando-o-site-à-api) descreve o que muda caso
a equipe decide reconectar o site à API.

### Estado verificado da publicação em produção

O site está publicado em **<https://aegisscan-zeta.vercel.app/>** (projeto
Vercel `aegisscan-zeta`). O estado abaixo foi verificado diretamente contra
o servidor e contra o **bundle JavaScript publicado**, não apenas por leitura
do código-fonte.

| Verificação | Resultado observado |
| --- | --- |
| `GET /` | `200`, HTTP/2, `server: Vercel`, `x-vercel-cache: HIT` |
| TLS | `strict-transport-security: max-age=63072000; includeSubDomains; preload` — HSTS com `preload` |
| HTML servido | idêntico a `frontend/index.html` (mesmo favicon SVG inline, mesmo `meta-theme-color`) |
| Assets | `/assets/index-Cntm5eTS.js` (252 KB) e `/assets/index-DqplV3y1.css` (20 KB) — nomes com hash do Vite |
| Estáticos de `public/` | `/favicon.svg` e `/icons.svg` respondem `200` (copiados para `dist/`) |
| Data do deploy | `last-modified: Wed, 21 Oct 2026 20:10:08 GMT` |
| `GET /saude` | **`404`** — não há backend atrás do domínio |
| `GET /api/saude` | **`404`** — não há proxy de API configurado |

E, no bundle publicado (`/assets/index-Cntm5eTS.js`):

| String procurada | Ocorrências | Conclusão |
| --- | --- | --- |
| `/analisar` | 0 | A rota da API não está no bundle |
| `sem_conexao` | 0 | `api.js` **não** foi empacotado |
| `analisarArquivos` / `analisarCodigo` / `analisarUrl` | 0 | idem |
| `multipart/form-data` | 0 | idem |
| `CWE-798` | 1 | O motor de regex local **está** no bundle |

Confirmação empírica da conclusão da seção anterior: **a versão publicada é a
de `HEAD` e não fala com nenhuma API.** O único endereço externo no bundle é
`https://site.com`, que é apenas o texto de exemplo do campo de URL
(`frontend/src/translate.js:12`).

### Armadilha: não há rewrite de SPA

`GET https://aegisscan-zeta.vercel.app/qualquer/caminho` responde **`404`**,
não o `index.html`. O projeto Vercel não tem `vercel.json` no repositório e,
portanto, nenhuma regra de *rewrite* para `index.html`.

Isso **não quebra o site hoje**, porque a navegação é feita por estado do
React (`paginaAtual` em `App.jsx:45`) e todos os links usam `href="#"` com
`preventDefault` — a URL nunca muda. Mas significa que:

- recarregar a página ou abrir um link direto para uma sub-rota devolve 404;
- qualquer refatoração futura para roteamento por URL (ou a adição de um
  roteador como o `react-router`) exige criar o `vercel.json` com o
  *rewrite* — ver [Apêndice C](#apêndice-c--riscos-e-lacunas-conhecidos),
  risco 13.

### Topologia-alvo

```text
                    Internet
                       │  HTTPS (443)
        ┌──────────────┴───────────────────────────┐
        │                                          │
┌───────▼────────────────────┐        ┌────────────▼──────────────────────┐
│  Vercel                    │        │  Host da API  [NECESSÁRIO CONFIRMAR]│
│  ─ Frontend (Vite)         │        │  ─ Nginx/Caddy :443 (TLS)         │
│  ─ Build: npm run build    │        │      │  auth + rate limit            │
│  ─ Output: dist/           │        │      ▼                             │
│  ─ CDN + HTTPS automático  │        │  ─ Uvicorn 127.0.0.1:8000         │
│  ─ sem dependência da API  │        │      (1 processo, sem auth,         │
└────────────────────────────┘        │       sem rate limit)               │
                                     │  ─ /tmp gravável (efêmero)          │
                                     └──────────────────────────────────────┘
```

O caminho entre o site e a API só existe depois que `App.jsx` for reconectado
a `src/api.js` (Apêndice D). No estado atual, as duas metades são
independentes.

## 1. Pré-requisitos

### 1.1 Para o site (Vercel)

| Item | Versão / valor | Origem da exigência |
| --- | --- | --- |
| Node.js | `^20.19.0 \|\| >=22.12.0` | `engines` do `vite@8.3.1` em `frontend/package-lock.json` |
| npm | o que acompanha o Node | nenhum piso declarado no repositório **[NECESSÁRIO CONFIRMAR]** |
| Conta Vercel | plano Hobby ou superior | [NECESSÁRIO CONFIRMAR] |
| Projeto Vercel | `aegisscan-zeta` — **já existe** e publica em <https://aegisscan-zeta.vercel.app/> | URL fornecido pela equipe; verificado respondendo `200` |
| Repositório no GitHub | `https://github.com/CAMPUSCEUB/AEGIS` (branch `main`) | `git remote -v` |

O `frontend/package.json` **não** declara `engines` e não existe `.nvmrc` no
repositório. Isso é seguro hoje porque o Node LTS mais recente da Vercel
(24.x) satisfaz `>=22.12.0`, mas a versão deixa de ser garantida pelo código.
Ver 2.1.

### 1.2 Para a API (host próprio)

| Item | Versão / valor | Origem |
| --- | --- | --- |
| Python | **>= 3.11** | `requires-python = ">=3.11"` em `TOOL/pyproject.toml`; o código usa `match/case` e `X \| None` |
| pip | o que acompanha o Python | **[NECESSÁRIO CONFIRMAR]** (sem piso declarado) |
| Sistema operacional | Linux | **[NECESSÁRIO CONFIRMAR]** — nenhum arquivo do projeto especifica SO suportado; `docs/instalacao.md:16` registra a mesma lacuna |
| Terminador TLS | Nginx, Caddy ou equivalente | **[NECESSÁRIO CONFIRMAR]** — não existe proxy no repositório |
| Supervisor do processo | systemd, ou nada (processo em primeiro plano) | **[NECESSÁRIO CONFIRMAR]** |
| Espaço em disco gravável | `/tmp` com folga para ~50 MB por requisição concorrente | `api.py:132` (`tempfile.TemporaryDirectory`) + limites de `api.py:41-42` |

### 1.3 Não é necessário

| Recurso | Situação |
| --- | --- |
| Banco de dados | **Não existe e não é necessário** — ver [seção 5](#5-banco-de-dados) |
| Redis / fila / cache | Não existem |
| S3 / armazenamento de objetos | Não existe |
| Provedor de e-mail, IA ou terceiros | Nenhum — o processo **não faz nenhuma chamada de saída** |
| Docker / Docker Compose | Não há imagem no repositório; usar apenas se a equipe decidir **criar** uma |

## 2. Configuração

### 2.1 Projeto Vercel (site)

Configuração no painel da Vercel (**Settings → Build and Deployment**), ou
equivalente em `vercel.json` — que **não existe** no repositório e teria de ser
criado.

| Campo | Valor | Observação |
| --- | --- | --- |
| Framework Preset | `Vite` | autodetectado pelo `vite.config.js` + `package.json` |
| Root Directory | `frontend` | é onde está o `package.json`; sem isso o build falha por não achar o script |
| Install Command | `npm install` | autodetectado a partir do `package-lock.json` (lockfile v3) |
| Build Command | `npm run build` | script `build` = `vite build` (`frontend/package.json:8`) |
| Output Directory | `dist` | padrão do Vite (`build.outDir`) — só o conteúdo deste diretório é publicado |
| Node.js Version | 24.x (padrão da Vercel) | ajustável em Settings → Build and Deployment → Node.js Version |

A configuração do projeto `aegisscan-zeta` já está funcionando: o deploy
publicado responde `200` com o bundle Vite esperado. Os valores acima são o
que a Vercel aplica por autodetecção — **[NECESSÁRIO CONFIRMAR]** se batem
com o que está gravado no painel.

Sobre a versão do Node: a Vercel usa por padrão o **LTS mais recente** (24.x
no momento) e permite escolher 22.x. Ambos satisfazem o requisito do Vite 8.
Como `frontend/package.json` não declara `engines`, a versão não fica fixada
pelo repositório — a configuração do painel é a única fonte de verdade. Para
fixá-la no código, seria preciso adicionar `engines.node` ao `package.json` ou
um `.nvmrc`, o que **não** foi feito aqui porque este documento não altera
arquivos do projeto.

**Variáveis de ambiente na Vercel.** Definição em **Settings → Environment
Variables**, com escopo por ambiente (Production / Preview / Development).

| Variável | Quando usar | Efeito |
| --- | --- | --- |
| `VITE_API_URL` | **Somente** após reconectar o site à API (Apêndice D) | URL base da API, embutida no bundle em tempo de build |

⚠️ **Nunca coloque segredo em variável `VITE_*`.** O Vite substitui
`import.meta.env.VITE_*` por literais durante o build; o valor fica visível no
JavaScript publicado. `VITE_API_URL` é apenas um endereço público — está
correto. Uma chave de API, senha ou token em `VITE_*` seria entregue a quem
visitar o site. Variáveis **sem** o prefixo `VITE_` nunca chegam ao bundle.

⚠️ **Variáveis são fixadas no build.** Alterar uma variável de ambiente na
Vercel **não** altera deployments já publicados; é preciso um novo
deploy/redeploy para o novo valor valer.

### 2.2 Variáveis de ambiente da API

As três variáveis abaixo são as **únicas** do backend e todas são opcionais.
Nenhum arquivo `.env` é carregado automaticamente: elas precisam estar no
ambiente do processo.

| Variável | Padrão | Valor em produção | Efeito |
| --- | --- | --- | --- |
| `OWASPSCAN_HOST` | `127.0.0.1` | `127.0.0.1` | Endereço em que o Uvicorn escuta (`api.py:230`) |
| `OWASPSCAN_PORTA` | `8000` | `8000` | Porta TCP (`api.py:231`) |
| `OWASPSCAN_ORIGENS` | `*` | origem real do site, ex.: `https://aegis.exemplo.edu.br` | Origens permitidas no CORS, separadas por vírgula (`api.py:47`) |

Regras obrigatórias em produção:

1. **`OWASPSCAN_ORIGENS` nunca pode ser `*`.** O padrão `*` permite que
   qualquer site chame a API em nome do usuário da rede. `docs/seguranca.md`
   classifica o CORS como `⚠️ PARCIAL` e exige restrição explícita fora de
   desenvolvimento.
2. **`OWASPSCAN_HOST` deve continuar `127.0.0.1`** enquanto a API não tiver
   autenticação própria. Definir `0.0.0.0` expõe um endpoint de análise
   aberto — sem autenticação, sem rate limit e sem registro de requisições.
   Exposição pública só é aceitável **atrás** de um proxy que aplique auth e
   limitação (seção 4.3).
3. Se `OWASPSCAN_ORIGENS` for restringido e o site for reconectado, a origem
   precisa incluir o domínio exato da Vercel (inclusive o esquema
   `https://`).

### 2.3 Configuração do motor — sem ação necessária

O motor não tem configuração. `TOOL/owaspscan/` lê apenas o que está no
código analisado. Os limites da API são **constantes no código**
(`api.py:41-42`), não variáveis de ambiente:

| Constante | Valor | Efeito quando excedido |
| --- | --- | --- |
| `MAXIMO_DE_ARQUIVOS` | 50 | HTTP `413` |
| `TAMANHO_MAXIMO_POR_ARQUIVO` | 1 000 000 bytes | HTTP `413` |

Alterá-los exige editar `api.py` **e** `TOOL/tests/test_api.py`, que importa
essas constantes.

## 3. Build

### 3.1 Build do site (executado pela Vercel)

```bash
npm install        # usa o frontend/package-lock.json (lockfile v3)
npm run build      # vite build  →  frontend/dist/
```

O `dist/` contém o HTML, o bundle JavaScript e o CSS. A Vercel publica
**apenas** o conteúdo desse diretório, servido pela CDN da Vercel.

Ensaio local idêntico ao build da Vercel:

```bash
cd frontend
npm install
npm run build
ls dist/
```

`npm ci` pode ser usado localmente para reproduzir exatamente o lockfile; a
Vercel usa `npm install` por autodetecção. `npm run preview` serve o `dist/`
para conferência local, mas **não** é um servidor de produção (a própria
documentação do Vite desaconselha o uso em produção) — na Vercel o papel é
desempenhado pela CDN.

`dist/` está no `.gitignore` (raiz e `frontend/`) e nunca é commitado.

Resultado esperado do build, observado na publicação em produção:

```text
dist/
├── assets/
│   ├── index-<hash>.css     (~20 KB)
│   └── index-<hash>.js      (~250 KB)
├── favicon.svg
├── icons.svg
└── index.html
```

Os arquivos de `frontend/public/` são copiados para a raiz do `dist/` sem
hash (é por isso que `/favicon.svg` e `/icons.svg` respondem `200` com a URL
estável). Os assets gerados recebem hash de conteúdo, o que permite cache
imutável na CDN.

### 3.2 Build da API

Não há etapa de build no repositório. A API é instalada como pacote Python:

```bash
cd TOOL
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install ".[api,linguagens]"
```

Observações:

- **Sem `-e` (editável) em produção.** O modo editável faz o venv apontar
  para a árvore de código; em produção o ideal é que o venv contenha a sua
  própria cópia, para que uma troca de código não afete o processo em execução
  antes do restart.
- **O extra `api`** traz `fastapi>=0.110`, `uvicorn>=0.29` e
  `python-multipart>=0.0.9`. Sem ele, `python -m owaspscan.api` falha com
  `ModuleNotFoundError: No module named 'fastapi'`.
- **O extra `linguagens`** traz `tree-sitter` e as gramáticas de
  JavaScript/TypeScript, Java, PHP e HTML. **Sem ele**, o motor continua
  funcionando, mas os arquivos dessas linguagens aparecem no relatório como
  falha de leitura com motivo `dependencia` (`TOOL/README.md:41-44`). Como a
  descrição da API no FastAPI anuncia essas linguagens (`api.py:68-71`),
  o extra deve ser instalado em produção.
- O núcleo do scanner **não tem dependência de terceiros** (`dependencies = []`).
  Se a API não for necessária, `pip install .` basta.

Não há lockfile Python no repositório — os extras têm **pisos** de versão
(`>=`), não tetos. A versão efetivamente instalada depende do momento da
instalação. **[NECESSÁRIO CONFIRMAR]** se a política exige pinagem exata.

## 4. Inicialização

### 4.1 Site (Vercel)

O projeto Vercel `aegisscan-zeta` já está criado e conectado ao repositório
GitHub. O deploy é disparado por push no branch `main`:

```bash
git push origin main
```

A Vercel detecta o push, executa o build (§ 3.1) e publica a nova versão.
Cada push para outro branch gera um **Preview Deployment** com URL própria.
Para um deploy manual:

```bash
npm install -g vercel
cd frontend
vercel            # preview
vercel --prod     # produção
```

### 4.2 API — preparação do host

Comandos a executar **uma vez**, como root. O usuário de sistema não precisa
de shell nem de home.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin aegis
sudo mkdir -p /opt/aegis
sudo chown -R aegis:aegis /opt/aegis
sudo -u aegis git clone https://github.com/CAMPUSCEUB/AEGIS.git /opt/aegis/repo
sudo -u aegis python3 -m venv /opt/aegis/repo/TOOL/.venv
sudo -u aegis /opt/aegis/repo/TOOL/.venv/bin/python -m pip install --upgrade pip
sudo -u aegis /opt/aegis/repo/TOOL/.venv/bin/python -m pip install "/opt/aegis/repo/TOOL[api,linguagens]"
```

O clone é feito com o usuário `aegis` para evitar o erro de
`detected dubious ownership` do Git em atualizações (§ 10.2).

### 4.3 API — serviço systemd

**Arquivo a criar**: `/etc/systemd/system/aegis-api.service`. Não existe
nada equivalente no repositório.

```ini
[Unit]
Description=AEGIS - API OWASP-Scan (FastAPI/Uvicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=aegis
Group=aegis
WorkingDirectory=/opt/aegis/repo/TOOL
Environment=OWASPSCAN_HOST=127.0.0.1
Environment=OWASPSCAN_PORTA=8000
Environment=OWASPSCAN_ORIGENS=https://aegis.exemplo.edu.br
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/aegis/repo/TOOL/.venv/bin/python -m owaspscan.api
Restart=on-failure
RestartSec=5

# O processo só escreve em /tmp (pasta temporária dos uploads).
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-api
sudo systemctl status aegis-api
```

Pontos que importam:

- **`PrivateTmp=true`** dá à API um `/tmp` isolado. Os uploads dos clientes
  (`api.py:132`) são gravados ali e destruídos ao fim de cada requisição; o
  namespace desaparece quando o serviço para. Nenhum volume persistente é
  necessário.
- **`ProtectSystem=strict`** deixa o sistema de arquivos somente-leitura
  exceto o que o serviço precisar escrever — que é apenas o `/tmp` privado.
  `PYTHONDONTWRITEBYTECODE=1` evita que o Python tente gravar `__pycache__`
  dentro do venv (em `/opt`, somente-leitura), o que produziria falhas
  silenciosas de cache.
- **`WorkingDirectory`** não é estritamente necessário (o pacote instalado é
  importável de qualquer diretório), mas deixa a operação previsível.
- **Um único processo.** `api.py:228-232` chama `uvicorn.run(app, host=...,
  port=...)` **sem o parâmetro `workers`** — a API sobe com um processo e um
  event loop. A análise é CPU-bound e roda no threadpool padrão do Starlette
  (`api.py:207`), mas o GIL serializa o trabalho em Python puro. Não há
  suporte a múltiplos workers sem alterar o código — **[NECESSÁRIO CONFIRMAR]**
  se a carga exigirá escala horizontal.
- **Sem TLS no Uvicorn.** `uvicorn.run` é chamado sem `ssl_keyfile` /
  `ssl_certfile` (`api.py:228-232`); o Uvicorn serve HTTP puro. O TLS é
  responsabilidade do proxy (§ 4.4).

### 4.4 API — proxy reverso com TLS

O projeto não tem proxy reverso. O trecho abaixo é para **Nginx**; Caddy,
Traefik ou Apache são equivalentes. **[NECESSÁRIO CONFIRMAR]** a escolha da
tecnologia e do provedor de certificado.

**Arquivo a criar**: `/etc/nginx/sites-available/aegis-api`.

```nginx
# Limite de corpo: 50 arquivos x 1 MB (limite da API) + folga de multipart.
# Este é também o único teto para o corpo JSON, que a aplicação não impõe.
client_max_body_size 52m;

# Limite de taxa por IP (a API não tem rate limit próprio).
limit_req_zone $binary_remote_addr zone=aegis:10m rate=30r/m;

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name api.aegis.exemplo.edu.br;

    ssl_certificate     /etc/letsencrypt/live/api.aegis.exemplo.edu.br/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.aegis.exemplo.edu.br/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Autenticação: a API não tem mecanismo próprio.
    auth_basic           "AEGIS";
    auth_basic_user_file /etc/nginx/aegis.htpasswd;

    location / {
        limit_req zone=aegis burst=10 nodelay;

        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # A análise é CPU-bound; sem timeout explícito o proxy usaria o padrão (60s).
        proxy_read_timeout 120s;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name api.aegis.exemplo.edu.br;
    return 301 https://$host$request_uri;
}
```

```bash
sudo htpasswd -c /etc/nginx/aegis.htpasswd aegis
sudo ln -s /etc/nginx/sites-available/aegis-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

Observações importantes:

- **A autenticação tem de ser externa.** A API não implementa API key, token,
  sessão ou qualquer verificação de identidade (`docs/seguranca.md`, seção
  "Autenticação": *inexistente*). `auth_basic` é o mínimo; uma API key em
  header (por exemplo, via `auth_request` ou um gateway) dá mais controle.
- **`client_max_body_size` é obrigatório**, não cosmético. O caminho JSON faz
  `await request.json()` antes de qualquer verificação de tamanho
  (`api.py:142`), então um corpo JSON gigante é carregado em memória sem
  limite pela aplicação — `docs/api.md` §"Limitações conhecidas" registra isso
  como limitação 2. O limite do nginx é a única barreira.
- **`limit_req` é a única proteção contra abuso de CPU.** A API não tem rate
  limit, e requisições simultâneas ilimitadas competem pelo mesmo processo
  único.
- **Renovação de certificado**: **[NECESSÁRIO CONFIRMAR]** — Let's Encrypt com
  `certbot --renew` via timer do systemd, ou certificado emitido pela
  autoridade certificadora da instituição. O caminho `/etc/letsencrypt/...`
  acima é ilustrativo.
- **Versão do Nginx**: a diretiva `http2 on;` usada acima exige Nginx
  **>= 1.25.1**. Em versões anteriores, o HTTP/2 é habilitado na própria
  diretiva `listen` (`listen 443 ssl http2;`), e a linha `http2 on;` deve ser
  removida para o Nginx não recusar a configuração.
- Se a API **não** for exposta publicamente (uso restrito a uma rede
  interna), o bloco de proxy pode ser simplificado para `listen 80` em
  `127.0.0.1` e a autenticação pode ser omitida.

### 4.5 API — alternativa em Vercel Functions

A Vercel também executa aplicações FastAPI como Serverless Function
(runtime Python, default 3.12). **Não é a configuração recomendada** para
este projeto, pelos seguintes motivos concretos:

- `api.py` **não é um nome de entrypoint reconhecido** pela Vercel (`app.py`,
  `index.py`, `server.py`, `main.py`, `wsgi.py`, `asgi.py`, ou
  `tool.vercel.entrypoint` em `pyproject.toml`). Seria preciso criar um
  arquivo de entrada — **alteração de código não feita aqui**.
- O filesystem da Function é somente-leitura, com `/tmp` gravável até 500 MB.
  A pasta temporária da API funciona, mas o limite é outro.
- Duração máxima da Function: 300 s por padrão (Hobby). O motor não impõe
  timeout de análise (`docs/api.md` §"Limitações conhecidas", item 3).
- Python 3.12+ é obrigatório na Vercel; o projeto declara `>=3.11`, o que
  satisfaz.
- A Function é dimensionada por CPU, o que combina bem com um serviço
  CPU-bound, mas introduz cold start e cobrança por tempo de CPU ativo.

**[NECESSÁRIO CONFIRMAR]** se a equipe quer explorar esta via. O caminho
padrão permanece: backend em host próprio, site na Vercel.

## 5. Banco de dados

**O projeto não tem banco de dados e não precisa de um.** Não há driver, ORM,
migration, seed, schema, connection string ou variável de ambiente de banco em
nenhum lugar de `TOOL/owaspscan/`. Verificação completa em
`docs/banco-de-dados.md`.

O que a API usa como armazenamento:

| Item | Detalhe |
| --- | --- |
| Pasta temporária | `tempfile.TemporaryDirectory(prefix="owaspscan-")` criada **por requisição** (`api.py:132`) |
| Conteúdo | os arquivos enviados pelo cliente, com nomes reduzidos ao nome-base |
| Destruição | automática na saída do bloco `with`, antes da resposta ser montada (`api.py:136`) |
| Persistência residual | nenhuma — nem em sucesso nem em falha |
| Capacidade | até 50 arquivos × 1 MB ≈ 50 MB por requisição, em disco, por um instante |

Implicações para o deploy:

- **Nada a migrar, nada para semear, nada para fazer backup.** O estado do
  sistema é zero.
- **O único requisito de armazenamento** é um `/tmp` gravável no host da API.
  Com `PrivateTmp=true` no systemd (§ 4.3), esse `/tmp` é isolado por
  namespace e some quando o serviço para.
- **Escala horizontal é trivial**: a API é stateless, então qualquer
  instância atende qualquer requisição; o custo é CPU. A ressalva é que
  `uvicorn.run` não expõe `workers` (`api.py:228-232`) — a escala exigiria
  múltiplos processos/instâncias, **[NECESSÁRIO CONFIRMAR]**.
- O navegador do visitante guarda apenas a preferência de tema em
  `localStorage` (chave `aegis-tema`) — está no cliente, não no servidor.

## 6. Serviços auxiliares

**Nenhum serviço auxiliar é necessário.** O produto é autocontido:

| Serviço auxiliar | Existe? | Observação |
| --- | --- | --- |
| Banco de dados | Não | ver [seção 5](#5-banco-de-dados) |
| Cache (Redis/Memcached) | Não | O relatório é recomputado a cada requisição |
| Fila / broker | Não | O `POST /analisar` é síncrono: a resposta só volta quando a análise termina |
| Object storage (S3) | Não | Nenhum upload é retido |
| Provedor de e-mail | Não | Nenhuma notificação |
| Provedor de IA / LLM | Não | O motor é análise estática determinística, sem rede |
| SSO / OAuth | Não | Não há contas de usuário |
| Observabilidade / APM | Não | **[NECESSÁRIO CONFIRMAR]** — ver [seção 8](#8-logs) |
| Service discovery / DNS | Não | Um único host da API **[NECESSÁRIO CONFIRMAR]** |

As únicas peças que existem **fora** do repositório e precisam ser operadas:

1. **Terminador TLS** (§ 4.4) — obrigatório para a API; no site, é nativo da
   Vercel.
2. **Autenticação e rate limit** (§ 4.4) — obrigatórios se a API for
   exposta fora da máquina, porque a aplicação não implementa nenhum dos dois.
3. **Plataforma de hospedagem** — Vercel para o site; **[NECESSÁRIO
   CONFIRMAR]** para a API.

O backend **não faz nenhuma chamada de rede de saída** — nenhum client HTTP,
telemetria ou atualização automática. O único `httpx` do projeto está no extra
`dev`, para os testes.

## 7. Verificação

Execute na ordem. Cada passo tem um resultado esperado determinístico a
partir do código.

### 7.1 Motor e API — no host

```bash
cd /opt/aegis/repo/TOOL

# 1. Suíte de testes (434 funções; 613 coletados por causa das
#    parametrizações).
.venv/bin/python -m pytest -v
# Esperado: todos passam, sem erro de coleta.

# 2. Métricas do motor contra o corpus rotulado.
.venv/bin/python -m owaspscan.metricas tests/amostras
# Esperado: precisão 1.00, recall 0.97, F1 0.98 (medido no corpus próprio).

# 3. CLI detectando severidade alta -> exit code 1.
.venv/bin/python -m owaspscan tests/amostras/vulneravel ; echo "exit=$?"
# Esperado: relatório com achados de severidade alta e exit=1.

# 4. Serviço no ar.
sudo systemctl status aegis-api
curl -s http://127.0.0.1:8000/saude
# Esperado: {"status":"ok","versao":"0.2.0"}
```

### 7.2 API — através do proxy (o que o cliente realmente usa)

```bash
# 5. TLS e autenticação.
curl -I https://api.aegis.exemplo.edu.br/saude
# Esperado: 401 sem credenciais; 200 com -u aegis:senha.

curl -s -u aegis:senha https://api.aegis.exemplo.edu.br/saude
# Esperado: {"status":"ok","versao":"0.2.0"}

# 6. Análise real (SQL Injection).
curl -s -u aegis:senha -X POST https://api.aegis.exemplo.edu.br/analisar \
  -H "Content-Type: application/json" \
  -d '{"codigo": "from flask import request\nimport sqlite3\ndef view():\n    sqlite3.connect(\"x.db\").execute(\"SELECT * FROM t WHERE id=\" + request.args[\"id\"])\n", "nome": "app.py"}'
# Esperado: JSON com "resumo" e "achados" contendo CWE-89.

# 7. Documentação interativa.
curl -s -u aegis:senha https://api.aegis.exemplo.edu.br/docs -o /dev/null -w '%{http_code}\n'
# Esperado: 200 (Swagger UI).
```

### 7.3 Site (Vercel)

```bash
# 8. Build local idêntico ao da Vercel.
cd frontend && npm install && npm run build && npm run lint
# Esperado: build sem erro e lint sem apontamentos.
```

No navegador, sobre **<https://aegisscan-zeta.vercel.app/>**:

| # | Verificação | Resultado esperado |
| --- | --- | --- |
| V1 | Abrir a URL de produção | A página do AEGIS carrega (logo "A", layout completo) |
| V2 | Alternar tema claro/escuro | A cor da aba (`meta-theme-color`) e o fundo mudam |
| V3 | Alternar idioma PT/EN | Todos os textos mudam |
| V4 | Navegar pelo menu (Como Usar, FAQ, Scripts, Termos, Privacidade) | As "páginas" trocam de conteúdo (navegação por estado do React, sem mudança de URL) |
| V5 | Aba FICHEIRO — enviar `docs/teste/script_frontend.js` | O painel lista 4 achados: CWE-94 (Code Injection), CWE-79 (DOM XSS), CWE-798 (credencial exposta) e CWE-319 (tráfego HTTP) |
| V6 | Aba CÓDIGO — colar um trecho | O painel mostra os achados do scan local (regex do navegador) |
| V7 | Aba URL — colar um endereço `http://` | O painel acusa tráfego não criptografado (CWE-319) |
| V8 | Painel → Vercel → Deployments | Status **Ready**, sem erro de build |

Checagem rápida pela linha de comando, contra a produção real:

```bash
curl -sI https://aegisscan-zeta.vercel.app/ | sed 's/\r//'
# Esperado: HTTP/2 200, server: Vercel, x-vercel-cache: HIT,
#           strict-transport-security com preload.

curl -s https://aegisscan-zeta.vercel.app/ | grep -o '/assets/index-[A-Za-z0-9_-]*\.\(js\|css\)'
# Esperado: os dois assets com hash do Vite.

curl -s -o /dev/null -w '%{http_code}\n' https://aegisscan-zeta.vercel.app/saude
# Esperado: 404 — confirma que o site publicado não depende de backend.
```

> V5–V7 exercitam a **análise local do navegador** (a demonstração), não a
> API. Ver [Escopo](#o-site-publicado-é-uma-demonstração-do-produto-não-um-cliente-da-api).

O motor de demonstração do site são 6 regras de expressão regular em
`REGRAS_SAST` (`App.jsx:32-39`). Serve para conferir que o painel renderiza:

| Regra | CWE | O que detecta |
| --- | --- | --- |
| `\b(eval\|exec\|Function)\s*\(` | CWE-94 | Code Injection (RCE) |
| `\b(SELECT\|INSERT\|UPDATE\|DELETE)\b.*\s(WHERE\|VALUES).*(+\|`\|\$\|%s)` | CWE-89 | SQL Injection por concatenação |
| `(password\|secret\|api_?key\|token\|...).*\s[:=]\s*['"]...['"]` | CWE-798 | Credencial fixa |
| `\b(innerHTML\|outerHTML\|document\.write)\s*=` | CWE-79 | DOM XSS |
| `\b(md5\|sha1)\s*\(` | CWE-327 | Hash fraco |
| `['"\`]http://(?!localhost\|127\.0\.0\.1)` | CWE-319 | Tráfego HTTP sem TLS |

Limitações conhecidas dessa demonstração: a aba FICHEIRO processa **apenas o
primeiro arquivo** selecionado (`App.jsx:159`), e a aba CÓDIGO usa um
`setTimeout` fixo de 1,2 s para simular o processamento (`App.jsx:137`).

## 8. Logs

### 8.1 Site (Vercel)

| Fonte | Onde | Observação |
| --- | --- | --- |
| Log de build | Vercel → projeto → Deployments → *deployment* → **Logs** | Saída de `npm install` e `npm run build`; é onde aparece erro de versão do Node ou de dependência |
| Log de runtime | — | **Não se aplica**: o site é 100% estático, sem funções de servidor, sem telemetria e sem chamadas de saída |
| Variáveis de ambiente | Vercel → **Settings → Environment Variables** | Valor de *Config* é legível; valor de *Secret* é somente-escrita |

### 8.2 API

**A API não tem logging de aplicação.** Não existe uso do módulo `logging` em
`TOOL/owaspscan/` nem middleware de log de requisições
(`docs/seguranca.md`, seção "Logs e auditoria"). O que existe é o **log de
acesso padrão do Uvicorn**, escrito em `stdout`.

| Fonte | Onde | Observação |
| --- | --- | --- |
| Acesso (Uvicorn) | `stdout` → journal (systemd) | Método, caminho, status e latência por requisição |
| Erros da aplicação | `stderr` → journal | Exceções não tratadas viram `500` do Starlette |
| Body das requisições | **Não existe** | Nenhum log registra o código enviado — coerente com a promessa de privacidade, mas significa que **abuso é indetectável** |

Comandos:

```bash
# Tempo real.
sudo journalctl -u aegis-api -f

# Últimas 200 linhas.
sudo journalctl -u aegis-api -n 200

# Intervalo de tempo.
sudo journalctl -u aegis-api --since "1 hour ago"

# Só requisições com erro.
sudo journalctl -u aegis-api -p err
```

Limitações a registrar:

- **Não há arquivo de log, nem rotação, nem retenção definida** pelo projeto.
  Sob systemd, a retenção é a do `journald` —
  **[NECESSÁRIO CONFIRMAR]** a política de retenção e se os logs devem ser
  enviados para um agregador externo.
- **Não há trilha de auditoria** — nem de quem analisou o quê.
- **Não há log de conteúdo**: o código do usuário nunca é registrado. Isso é
  intencional (privacidade) e também significa que não é possível reconstruir
  uma análise a partir dos logs.
- **A API não registra o próprio start** de forma estruturada; a única
  verificação de sanidade é `GET /saude`, que devolve `{"status":"ok","versao":
  "0.2.0"}` (`api.py:171-173`).
- O proxy reverso adiciona uma segunda camada de log (Nginx), que é onde o
  `auth_basic` e o `limit_req` produzem evidência de bloqueio.

## 9. Parada

### 9.1 Site (Vercel)

O site é estático, sem processo de servidor a encerrar.

| Objetivo | Procedimento |
| --- | --- |
| Reverter para uma versão anterior | Vercel → Deployments → deployment alvo → **⋯** → **Redeploy** (imediato) |
| Interromper novas publicações | Desconectar a integração Git em Settings → Git, ou remover o branch de produção |
| Tirar o site do ar | Vercel → projeto → **Settings** → Domains / remover o domínio, ou remover o projeto |

O site publicado em <https://aegisscan-zeta.vercel.app/> é estático e não tem
processo de servidor a encerrar — a "parada" é sempre uma operação de
configuração na plataforma.

Rollback por *redeploy* é a operação correta: não há banco de dados, o que
mudou entre versões é apenas HTML/CSS/JS estático.

### 9.2 API

```bash
# Parada graciosa.
sudo systemctl stop aegis-api

# Desabilitar a inicialização automática no boot.
sudo systemctl disable aegis-api

# Estado.
sudo systemctl status aegis-api
```

O que acontece no `stop`:

1. O systemd envia **SIGTERM**. O Uvicorn trata o sinal e encerra com
   shutdown gracioso, permitindo que as requisições em andamento terminem.
2. Requisições interrompidas no meio podem receber `502`/`504` do proxy; o
   cliente deve reenviar.
3. O `/tmp` privado é destruído com o namespace. Como a pasta temporária de
   cada requisição já é apagada ao final do processamento
   (`api.py:132-136`), **não sobra resíduo** de uploads. Nenhum backup é
   necessário.
4. Nenhum estado é perdido: a API é stateless e não tem banco.

### 9.3 Parada de emergência

```bash
# Se o processo estiver travado e não responder ao SIGTERM.
sudo systemctl kill -s SIGKILL aegis-api
sudo systemctl restart aegis-api
```

### 9.4 Ordem recomendada

Ao derrubar o conjunto, **o site pode ficar no ar** — ele não depende da API
no estado atual. Ao subilo, **suba a API primeiro** e o site depois, para que
o Apêndice D (site reconectado) não encontre erros de análise.

## 10. Atualização

### 10.1 Site (Vercel)

O site não tem artefato próprio em produção: o que a Vercel publica é
reconstruído a partir do código no branch de produção. A atualização é, portanto,
um merge normal no repositório.

```bash
git checkout main
git pull origin main
# ... aplica as alterações (commit + merge) ...
git push origin main       # dispara o build e a publicação
```

O processo é:

1. Push em `main` → a Vercel executa o build e publica.
2. Se o build falhar, o deployment anterior **continua no ar** — a Vercel não
   promove um build quebrado.
3. **Reverter**: redeploy de um deployment anterior (§ 9.1).

Pontos de atenção:

- **O push precisa alterar algo.** Um `git push` sem commits novos não
  dispara deploy — a Vercel trata como "nada a publicar".
- **Variáveis de ambiente exigem novo deploy.** O valor do `VITE_API_URL` (e
  qualquer outro `VITE_*`) fica congelado no bundle no momento do build.
  Alterar a variável sem redeploy não muda nada no site publicado.
- **Não há CI.** O merge vai direto para build e publicação. Rodar
  `npm run lint` e `npm run build` localmente antes do merge é a única
  verificação disponível.
- Se for necessário fixar a versão do Node no repositório, isso exige alterar
  `frontend/package.json` (campo `engines`) ou adicionar `.nvmrc` — **fora do
  escopo deste documento**, que não altera arquivos do projeto.

### 10.2 API

```bash
cd /opt/aegis/repo
sudo -u aegis git pull origin main

# Reinstalar as dependências (o pyproject.toml pode ter mudado).
sudo -u aegis /opt/aegis/repo/TOOL/.venv/bin/python -m pip install --upgrade pip
sudo -u aegis /opt/aegis/repo/TOOL/.venv/bin/python -m pip install "/opt/aegis/repo/TOOL[api,linguagens]"

# Testar antes de reiniciar.
cd /opt/aegis/repo/TOOL
sudo -u aegis .venv/bin/python -m pytest -q

# Reiniciar.
sudo systemctl restart aegis-api
sudo systemctl status aegis-api
curl -s http://127.0.0.1:8000/saude
# Esperado: {"status":"ok","versao":"0.2.0"}
```

Cuidados:

- **A versão é duplicada em dois lugares** e precisa ser alterada nos dois:
  `TOOL/pyproject.toml` (`version = "0.2.0"`) e
  `TOOL/owaspscan/varredura.py:41` (`VERSAO = "0.2.0"`). A constante `VERSAO`
  aparece no relatório e na resposta de `/saude`. `docs/configuracao.md` §3
  registra essa duplicação.
- **Instalar antes de reiniciar.** Se o `pip install` falhar, o processo em
  execução continua com o código antigo — o restart só acontece se a
  instalação deu certo.
- **`git pull` com arquivos alterados localmente** falha. O clone é feito
  como `aegis` e não deve ser editado.
- **Não há CI** — os testes rodam apenas localmente. Rodar `pytest` antes do
  restart (passo acima) é a salvaguarda disponível.
- **Rollback**: `git checkout <tag-anterior>` + `pip install` + `systemctl
  restart`.

### 10.3 Ordem de atualização

1. Atualizar e reiniciar a **API**.
2. Verificar `GET /saude` (§ 7.1, passo 4).
3. Atualizar o **site** (push em `main`).
4. Verificar o site no navegador (§ 7.3).

Se o site estiver reconectado à API (Apêndice D), a API precisa estar no ar
**antes** do novo deploy do site, para não haver uma janela em que o bundle
novo aponta para um backend indisponível.

## Apêndice A — Referência de variáveis de ambiente

| Variável | Componente | Momento | Padrão | Secret? |
| --- | --- | --- | --- | --- |
| `OWASPSCAN_HOST` | API | Runtime (processo) | `127.0.0.1` | Não |
| `OWASPSCAN_PORTA` | API | Runtime (processo) | `8000` | Não |
| `OWASPSCAN_ORIGENS` | API | Runtime (processo) | `*` | Não |
| `VITE_API_URL` | Site | Build | `/api` (fallback em `api.js:4`) | Não — é embutido no bundle público |
| `OWASPSCAN_API` | Site (dev) | Runtime do `vite dev` | `http://127.0.0.1:8000` | Não |

Nenhuma variável do projeto precisa ser secreta — o sistema não tem banco,
usuário ou credencial de serviço. Em particular, **nada** deve ir para uma
variável `VITE_*`, porque o valor é publicado no bundle do navegador.

Variáveis de plataforma (não do projeto): `VERCEL_ENV`, `VERCEL_URL`,
`VERCEL_GIT_PROVIDER` e afins são injetadas pela Vercel; as que começam com
`VITE_` ficam disponíveis no bundle.

## Apêndice B — Mapa de portas

| Serviço | Porta | Escuta | Quem acessa | Quem define |
| --- | --- | --- | --- | --- |
| API (Uvicorn) | `8000` | `127.0.0.1` (produção) | Só o proxy reverso, localmente | `OWASPSCAN_PORTA` (`api.py:231`) |
| Proxy reverso (Nginx) | `80` / `443` | Interface pública | Internet | Configuração do proxy |
| Site (Vercel) | `443` | CDN da Vercel | Internet | Plataforma |
| Vite (dev) | `5173` | `localhost` | Só o desenvolvedor | `vite.config.js` (sem `server.port`) |

## Apêndice C — Riscos e lacunas conhecidos

Registrado em `docs/seguranca.md` e `docs/api.md`; reproduzido aqui porque
determina como a API pode ser exposta.

| # | Risco | Onde | Mitigação no deploy |
| --- | --- | --- | --- |
| 1 | **Sem autenticação** | `api.py` inteiro | `auth_basic` (ou API key) no proxy (§ 4.4) |
| 2 | **Sem rate limit** — abuso de CPU | — | `limit_req` no proxy (§ 4.4) |
| 3 | **`OWASPSCAN_ORIGENS=*`** por padrão | `api.py:47` | Definir explicitamente (§ 2.2) |
| 4 | **Corpo JSON sem limite** antes do parse | `api.py:142` | `client_max_body_size` no nginx (§ 4.4) |
| 5 | **Sem timeout de análise** | — | `proxy_read_timeout` no nginx (§ 4.4) |
| 6 | **Um único processo**, sem `workers` | `api.py:228-232` | Múltiplas instâncias **[NECESSÁRIO CONFIRMAR]** |
| 7 | **Sem logs de aplicação** — abuso indetectável | — | Log do proxy + journal (§ 8) |
| 8 | **TLS não é responsabilidade da aplicação** | `api.py:228-232` | Terminador TLS (§ 4.4); Vercel faz isso no site |
| 9 | **Sem CI/CD** — deploy não é bloqueado por testes | — | Rodar `pytest` / `npm run build` antes do merge (§ 10) |
| 10 | **Versão duplicada** em `pyproject.toml` e `varredura.py` | `varredura.py:41` | Alterar as duas juntas (§ 10.2) |
| 11 | **Sem testes de frontend** | — | `npm run lint` + verificação manual (§ 7.3) |
| 12 | **Site publicado não exercita a API** | `App.jsx` | Apêndice D |
| 13 | **Sem rewrite de SPA** — caminhos profundos devolvem `404` | ausência de `vercel.json` | Criar `vercel.json` com *rewrite* para `index.html` antes de adotar rotas por URL |

## Apêndice D — Conectando o site à API

Se a equipe decidir que o site deve de fato chamar a API (o que **não** é o
estado atual), o trabalho tem duas partes: uma alteração de código no frontend
e uma mudança de configuração na infraestrutura. Esta seção descreve o que
precisa mudar; **nada aqui foi aplicado**.

### D.1 Alteração de código (frontend)

`frontend/src/api.js` e `frontend/src/Resultado.jsx` já existem e já estão
corretos — `api.js` implementa os três formatos de envio (multipart, JSON e
URL) e `Resultado.jsx` renderiza o painel no estilo da interface atual. O que
falta é o `App.jsx` voltar a importá-los, como fazia o commit `79ab534`:

```jsx
import { analisarArquivos, analisarCodigo, analisarUrl } from './api';
import Resultado from './Resultado';
```

E a substituir a análise local por regex (`analisarTexto` / `REGRAS_SAST`) pela
chamada à API. A seção 5 de `docs/teste/ROTEIRO_DE_DEMONSTRACAO.md` traz o resultado
esperado para esse fluxo (8 achados em `docs/teste/app_vulneravel.py`).

### D.2 Configuração (frontend na Vercel)

Definir `VITE_API_URL` em **Settings → Environment Variables**, com escopo
**Production** e **Preview**, apontando para a URL pública da API:

```bash
VITE_API_URL=https://api.aegis.exemplo.edu.br
```

Sem essa variável, `api.js:4` faz fallback para `/api` — o que pressupõe que
o mesmo domínio sirva o site e encaminhe `/api` para o backend. Na Vercel isso
significaria um **rewrite** em `vercel.json` para a URL da API; com
`VITE_API_URL` explícito, não é necessário.

A URL da API fica **embutida no bundle público**. Isso é aceitável (é um
endereço, não um segredo), mas significa que a URL do backend é pública.

### D.3 Configuração (API)

- `OWASPSCAN_ORIGENS` passa a ser obrigatório e deve listar a origem exata do
  site na Vercel (por exemplo, `https://aegis.vercel.app` e, se houver
  domínio próprio, `https://aegis.exemplo.edu.br`). O middleware CORS só
  libera `GET` e `POST` (`api.py:76`) — o suficiente para `/analisar`.
- A API precisa estar **alcançável a partir da internet**, porque o navegador
  chama a API diretamente a partir da máquina do visitante. Isso significa:
  `OWASPSCAN_HOST=0.0.0.0` **e** proxy TLS com autenticação (§ 4.4).
  Alternativa: fazer o proxy encaminhar `/api` para o backend e manter
  `OWASPSCAN_HOST=127.0.0.1` — nesse caso a API continua privada.
- **Cuidado com `allow_credentials`**: não está habilitado (`api.py:73-78`),
  então o CORS não combina com cookies de sessão. Autenticação por header
  funciona; autenticação por cookie exigiria revisar o middleware.

### D.4 Consequências

- O site passa a depender da disponibilidade da API: se o backend cair, as
  abas de análise param de funcionar (e o usuário vê o erro
  `sem_conexao` de `api.js:11`).
- A promessa de privacidade passa a valer de ponta a ponta: o código é
  enviado ao backend, gravado em `/tmp` por requisição e destruído ao final
  (`api.py:132-136`).
- O texto de privacidade exibido no site passa a corresponder ao
  comportamento real — hoje ele descreve uma garantia que a demonstração
  local não exerce.

## Referências

- Instalação e verificação passo a passo: [`docs/instalacao.md`](instalacao.md)
- Inventário de configurações e variáveis: [`docs/configuracao.md`](configuracao.md)
- Contrato da API HTTP: [`docs/api.md`](api.md)
- Ausência de persistência: [`docs/banco-de-dados.md`](banco-de-dados.md)
- Riscos e recomendações de segurança: [`docs/seguranca.md`](seguranca.md)
- Arquitetura e limitações: [`docs/arquitetura.md`](arquitetura.md)
- Documentação do motor e cobertura: [`TOOL/README.md`](../TOOL/README.md)
- Roteiro de demonstração e resultado esperado: [`docs/teste/ROTEIRO_DE_DEMONSTRACAO.md`](teste/ROTEIRO_DE_DEMONSTRACAO.md)
