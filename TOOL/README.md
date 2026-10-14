# OWASP-Scan

Analisador estatico de vulnerabilidades OWASP Top 10 em codigo Python
(Django/Flask), baseado em AST e taint tracking. Projeto de Iniciacao
Cientifica — Ciencia da Computacao, UniCEUB.

## Cobertura

Cada achado e classificado pela CWE, e a categoria OWASP vem da lista
oficial "List of Mapped CWEs" do Top 10:2021 — nao do tema do detector.
Por isso "hash fraco de senha", tema de autenticacao, aparece em A02.

| CWE | Vulnerabilidade | OWASP 2021 | Tecnica | Confianca |
| --- | --- | --- | --- | --- |
| CWE-89 | SQL Injection | A03 | taint | alta/media |
| CWE-79 | Cross-Site Scripting | A03 | taint | alta/media |
| CWE-639 | IDOR | A01 | heuristica | baixa (candidato) |
| CWE-22 | Path Traversal | A01 | taint + guardas | alta/media |
| CWE-601 | Open Redirect | A01 | taint + guardas | alta/media |
| CWE-352 | CSRF desligado | A01 | estrutural / heuristica | alta ou baixa |
| CWE-862 | Rota sem autorizacao | A01 | heuristica | baixa (candidato) |
| CWE-916 | Hash rapido de senha | A02 | estrutural (nome) | media |
| CWE-256 | Senha em texto puro | A04 | taint | alta/media |
| CWE-611 | XXE | A05 | estrutural + taint | alta/media |
| CWE-614 | Cookie sem Secure | A05 | estrutural | alta/media |
| CWE-1004 | Cookie sem HttpOnly | A05 | estrutural | alta/media |
| CWE-287 | JWT sem verificacao | A07 | estrutural | alta |
| CWE-307 | Login sem rate limit | A07 | heuristica | baixa (candidato) |
| CWE-613 | Sessao longa demais | A07 | estrutural | alta |
| CWE-798 | Credencial fixa (.py e configuracao) | A07 | estrutural | alta/media |

## Ambiente

    python3 -m venv .venv
    .venv/bin/python -m pip install -e ".[dev,linguagens]"

## Outras linguagens

Alem de Python, a ferramenta analisa JavaScript/TypeScript (Node/Express,
Koa, DOM, React) Java (Servlet, Spring MVC/Security, JDBC/JPA), PHP (mysqli/PDO,
Laravel, WordPress) e HTML (JavaScript embutido e formularios sem token CSRF). Como a stdlib so tem parser de Python, essas linguagens usam
o tree-sitter, instalado pelo extra opcional `[linguagens]`; sem ele, o nucleo
continua funcionando e os arquivos dessas linguagens aparecem no relatorio como
falha de leitura com motivo `dependencia`.

A deteccao segue o mesmo principio do nucleo: AST (arvore do tree-sitter) e
taint tracking intraprocedural, nunca regex. Cada linguagem e um perfil em
`owaspscan/poliglota/` com fontes, sinks e sanitizadores.

| Linguagem | Extensoes | CWEs |
| --- | --- | --- |
| JavaScript / TypeScript | .js .mjs .cjs .jsx .ts .tsx | 89, 79, 22, 601, 798 |
| Java (Servlet, Spring, JDBC/JPA) | .java | 89, 79, 22, 601, 798, 611, 614, 1004, 352 |
| PHP (puro, Laravel, WordPress) | .php | 89, 79, 22, 601, 798, 611, 614, 1004 |
| HTML | .html .htm | JS de `<script>` e `on*` (como JavaScript) + 352 (candidato) |

Arquivos gerados (`.min.js`, `.bundle.js`, `.d.ts`), `node_modules` e
arquivos acima de 1 MB ficam de fora.

## Uso

Com o venv ativo (`source .venv/bin/activate`), o `pip install -e .` instala
o comando `owasp-scan`:

    owasp-scan caminho/do/projeto
    owasp-scan app.py --json | jq '.resumo'
    owasp-scan .env                   # arquivo de configuracao isolado

`python -m owaspscan ...` continua funcionando.

Codigos de saida: `0` sem achado de severidade alta, `1` com achado alto,
`2` erro de uso. Candidatos heuristicos (confianca baixa) nao alteram o
codigo de saida — nao seria honesto quebrar um build com base em suposicao.

## API HTTP (para o site)

Dependencia opcional; o nucleo continua so com a stdlib.

    .venv/bin/python -m pip install -e ".[api,linguagens]"
    .venv/bin/python -m owaspscan.api        # http://127.0.0.1:8000/docs

Host e porta: `OWASPSCAN_HOST` e `OWASPSCAN_PORTA`. Origens CORS permitidas:
`OWASPSCAN_ORIGENS` (separadas por virgula; padrao `*`).

`POST /analisar` aceita JSON **ou** formulario — use o que for mais facil no site.
A linguagem de cada arquivo (e do codigo colado) vem da extensao do `nome`:
`{"codigo": "...", "nome": "app.js"}` e analisado como JavaScript.

**JSON** (texto colado e/ou arquivos lidos como texto):

    {"codigo": "...", "nome": "app.py",
     "arquivos": [{"nome": "views.py", "conteudo": "..."}]}

```js
const resposta = await fetch("http://127.0.0.1:8000/analisar", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ codigo: textarea.value }),
});
const resultado = await resposta.json();   // resultado.resumo, resultado.achados
```

**Formulario** (`multipart/form-data`, upload direto de `<input type="file" multiple>`):
campos `codigo`, `nome` e `arquivos` (repetivel).

```js
const form = new FormData();
for (const f of input.files) form.append("arquivos", f);
const resultado = await (await fetch("http://127.0.0.1:8000/analisar", { method: "POST", body: form })).json();
```

A resposta e exatamente o JSON de `--json` (`para_dict`), com `raiz` igual a
`"envio"`. Arquivos aceitos: `.py` e configuracao (`.env`, YAML, JSON, INI,
TOML, `.properties`). O codigo enviado nunca e executado, so parseado. Nomes
de arquivo sao reduzidos ao nome-base; limites: 50 arquivos, 1 MB cada.
Erros vem como `{"detail": "..."}`: `400` envio vazio, tipo nao suportado ou
nome repetido; `413` grande demais; `415` Content-Type errado; `422` JSON invalido.

O site em `frontend/` ja consome esta API (proxy `/api` no Vite); veja
[frontend/README.md](../frontend/README.md) e o roteiro de teste em
[docs/teste/ROTEIRO_DE_TESTE.md](../docs/teste/ROTEIRO_DE_TESTE.md).

## Testes

    .venv/bin/python -m pytest -v

## Limitacoes declaradas do motor

Preferimos confianca calibrada a cobertura inflada. O motor de taint e:

1. **Intraprocedural.** Cada funcao e analisada isoladamente; o taint nao
   atravessa a fronteira de chamada entre funcoes definidas no projeto.
   Fluxo do tipo `def a(): b(request.args["id"])` nao e seguido ate `b`.
2. **Insensivel a fluxo.** Se um nome recebe dado contaminado em qualquer
   ponto do escopo, conta como contaminado no escopo inteiro. Cobre laços e
   ramos `if/else` sem CFG, ao custo de falso positivo quando apenas um dos
   ramos contamina.
3. **Cego a arquivos de template.** A analise e de codigo Python; um
   `|safe` dentro de um `.html` do Jinja2 nao e visto. `render_template`
   e tratado como caminho seguro por causa do auto-escape.
4. **Pessimista em chamadas desconhecidas.** `y = f(x)` com `x` contaminado
   contamina `y`. Evita falso negativo silencioso, que e o pior erro para
   uma ferramenta de seguranca, ao custo de falso positivo quando `f`
   sanitiza.

5. **Guardas sao insensiveis a fluxo.** Em path traversal e open redirect,
   uma validacao (`realpath` + `startswith`, `url_has_allowed_host_and_scheme`)
   presente numa condicao do escopo suprime o achado sobre o valor validado;
   o motor nao confirma que o ramo de falha de fato aborta.

## Calibracao de confianca

O campo `confianca` carrega informacao sobre a cadeia fonte -> sink, nao a
gravidade da CWE:

- **alta**: a fonte alcanca o sink por operacoes de string diretas, em fluxo
  incondicional dentro do escopo.
- **media**: a cadeia passa por funcao nao analisada ou por ramo condicional,
  entao o motor nao viu o caminho inteiro.
- **baixa**: reservada a deteccao heuristica (IDOR), que reporta candidatos.

Nos detectores **estruturais** (configuracao, decorators, chamadas de
biblioteca), nao ha cadeia fonte -> sink; ali `confianca` mede a certeza de
que o padrao inseguro esta presente: `alta` quando o codigo o declara
literalmente (`resolve_entities=True`, `@csrf_exempt`, `verify=False`),
`media` quando depende de algo que a analise nao ve (versao do lxml,
variavel de ambiente que pode existir em producao, nome de identificador).

Sanitizacao nao rebaixa confianca: quando neutraliza a CWE em questao, remove
o achado. Cada sanitizador declara **quais CWEs neutraliza** — `int()` defende
SQL Injection e XSS; `html.escape()` defende XSS e **nao** defende SQL
Injection. Tratar sanitizacao como absoluta seria falso negativo. O mesmo
vale para os novos detectores: `secure_filename` defende CWE-22 e nada mais;
`url_for` defende CWE-601; `generate_password_hash`/`bcrypt` defendem CWE-256
— e `md5` tambem tira a senha do texto puro (CWE-256), mas continua sendo
reportado como hash fraco (CWE-916).

## IDOR e heuristico

O detector de CWE-639 reporta **candidatos**, nunca vulnerabilidades
confirmadas: `confianca` sempre `baixa` e a descricao comeca por
"Candidato a IDOR (requer revisao manual)". A razao e estrutural — o
controle de acesso pode morar num middleware, num decorator proprio ou na
camada de servico, fora do que uma analise intraprocedural enxerga.

Dois sinais suprimem o candidato: filtro por dono na propria consulta
(`filter_by(id=pid, user=current_user)`) e decorator de autorizacao na view
(`@permission_required`). `@login_required` **nao** suprime: autenticar nao e
autorizar.

Uma consequencia util: parametrizar a query resolve CWE-89 e nao resolve
CWE-639. As amostras em `tests/amostras/seguro/` sao seguras para a CWE que
nomeiam, nao para todas.

## Candidatos heuristicos alem do IDOR

Seguem a mesma regra do IDOR — `confianca` baixa, descricao que comeca por
"Candidato a ..." e nega afirmar vulnerabilidade, sem efeito no codigo de
saida:

- **CWE-862 rota sem autorizacao**: rota POST/PUT/PATCH/DELETE sem nenhum
  decorator de autenticacao/autorizacao nem checagem no corpo, ou rota de
  `/admin` sem checagem de papel. `@login_required` basta para rota comum e
  **nao** basta para `/admin`. Rotas publicas por natureza (login, cadastro,
  webhook) sao ignoradas; um `before_request` no arquivo suprime todas.
- **CWE-352 app sem CSRFProtect**: app Flask com rota que altera estado e
  nenhum `CSRFProtect`/`FlaskForm` no arquivo (a protecao pode estar em
  outro modulo). Rotas com `@jwt_required` nao contam: token no cabecalho
  nao e enviado pelo navegador sozinho.
- **CWE-307 login sem limite**: rota POST de login sem `@limiter.limit`,
  sem `Limiter(default_limits=...)` e sem contagem de tentativas visivel.

## XXE: o que nao e reportado

`xml.etree`, `minidom` e `xml.sax` da stdlib nao resolvem entidades
externas desde o Python 3.7.1 e nao sao acusados. O risco restante deles,
expansao recursiva ("billion laughs", CWE-776), esta fora do escopo. O
lxml e acusado com confianca alta quando o parser e configurado para
resolver entidades, e media quando recebe dado da requisicao com o parser
padrao (o comportamento padrao mudou na versao 5.0, invisivel a analise).

## Credenciais fixas (CWE-798)

A decisao tem duas metades: o **nome** diz que e credencial (`password`,
`senha`, `secret`, `token`, `api_key`...), exceto quando e metadado
(`password_min_length`, `token_url`, `token_type`); e o **valor** e um
literal plausivel, nao placeholder (`${VAR}`, `<sua-chave>`, `****`) nem
referencia (caminho, nome de variavel de ambiente). Senhas fracas como
`changeme` ou `password` **sao** reportadas: sao credenciais reais quando
chegam a producao.

No codigo Python, alem de atribuicoes, sao vistos: argumentos nomeados,
chaves de dicionario, defaults de parametro, fallback de `os.getenv`
(confianca media), `auth=(u, p)`, `smtp.login(u, p)`, `create_superuser`
com senha posicional, comparacao com literal (senha-mestra) e URL com
senha embutida. O trecho do relatorio **mascara o segredo**: a ferramenta
nao pode ser o vazamento que denuncia.

**Excecao declarada ao principio "somente AST"**: arquivos de configuracao
nao sao Python. `.env`, `.properties`, INI e TOML sao lidos pela gramatica
de linha do formato; JSON pelo parser da stdlib; YAML (sem parser na stdlib)
por pares `chave: valor` e itens `- CHAVE=valor`, sem interpretar escalares
de bloco, multi-linha nem ancoras. Arquivos-modelo (`.env.example`) saem com
severidade baixa.

## Avaliacao

    .venv/bin/python -m owaspscan.metricas tests/amostras

O gabarito mora nas proprias amostras, como comentario na linha do sink:

    cursor.execute("SELECT ... " + ident)   # achado: CWE-89, CWE-639
    cursor.execute(consulta)                # limitacao: CWE-89 fluxo interprocedural

`achado` marca vulnerabilidade que a ferramenta deve encontrar; `limitacao`
marca vulnerabilidade real que sabemos nao encontrar. **Limitacao declarada
conta como falso negativo**: declarar a falha nao a transforma em acerto, e
por isso o recall de CWE-89 e menor que 1.

Resultado atual sobre o corpus (25 arquivos Python e 9 de configuracao
analisados, 1 com erro de sintaxe proposital, 16 CWEs): precisao 1.00,
recall 0.98, F1 0.99 no geral; os dois falsos negativos sao as limitacoes
interprocedurais declaradas (CWE-89 e CWE-22).

As amostras de `tests/amostras/seguro/` sao seguras para a CWE que nomeiam,
nao para todas: quando um detector novo encontra outra CWE real numa amostra
antiga (o open redirect ja comentado em `seguro/flask_xss.py`, por exemplo),
a linha e rotulada no gabarito em vez de a amostra ser "limpa" para inflar
a precisao.

**Limite de validade**: corpus proprio, pequeno e construido junto com a
ferramenta. Estes numeros medem consistencia interna, NAO generalizacao.
Comparar com a literatura exige corpus externo (OWASP Benchmark, PyGoat).

## Estado

- Fase 0: contrato interno de achado e mapeamento CWE -> OWASP.
- Fase 1: camada AST (descoberta, parse resiliente, localizacao de nos).
- Fase 2: catalogo de fontes (Flask) e motor de taint intraprocedural.
- Fase 3: detector de SQL Injection (CWE-89) sobre sinks DB-API 2.0.
- Fase 4: sanitizacao por CWE e confianca calibrada pela procedencia.
- Fase 5: detector de Cross-Site Scripting refletido (CWE-79).
- Fase 6: detector heuristico de IDOR (CWE-639), reportando candidatos.
- Fase 7: resumo executivo em texto e JSON com metadados de execucao.
- Fase 8: varredura ponta-a-ponta e CLI (`python -m owaspscan`).
- Fase 9: avaliacao contra corpus rotulado (VP/FP/FN, precisao e recall).
- Fase 10: mapa CWE -> OWASP estendido (lista oficial 2021) e consultas
  estruturais (importacoes, configuracao, rotas).
- Fase 11: XXE (CWE-611) em lxml e SAX.
- Fase 12: path traversal (CWE-22) e open redirect (CWE-601) por taint.
- Fase 13: CSRF desligado (CWE-352) e rota sem autorizacao (CWE-862).
- Fase 14: JWT sem verificacao, hash fraco e texto puro de senha, cookies,
  expiracao de sessao e login sem limite de tentativas.
- Fase 15: credenciais fixas no codigo Python (CWE-798).
- Fase 16: credenciais em arquivos de configuracao (CWE-798).
- Fase 17: documentacao da cobertura ampliada e versao 0.2.0.
- Fase 18: API HTTP (POST /analisar) com FastAPI — dependencia opcional
  (extra `[api]`); o nucleo continua so com a stdlib.
- Fase 19: API aceita JSON alem de formulario e sobe com
  `python -m owaspscan.api` (ver secao "API HTTP (para o site)").
- Fase 20: site (`frontend/`) ligado a API e roteiro de teste em `docs/teste/`.
- Fase 21: comando `owasp-scan` instalado via `[project.scripts]`.
- Fase 22: motor poliglota sobre tree-sitter (extra opcional `[linguagens]`)
  e perfil JavaScript/TypeScript.
- Fase 23: perfil Java (Servlet, Spring, JDBC/JPA) com XXE, cookie e CSRF.
- Fase 24: perfil PHP (mysqli/PDO, Laravel, WordPress).
- Fase 25: HTML (JavaScript embutido e formularios sem token CSRF).
- Fase 26: API, CLI e site aceitam as novas linguagens.
