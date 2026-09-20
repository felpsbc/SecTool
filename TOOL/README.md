# OWASP-Scan

Analisador estatico de vulnerabilidades OWASP Top 10 em codigo Python
(Django/Flask), baseado em AST e taint tracking. Projeto de Iniciacao
Cientifica — Ciencia da Computacao, UniCEUB.

## Ambiente

    python3 -m venv .venv
    .venv/bin/python -m pip install -e ".[dev]"

## Uso

    python -m owaspscan caminho/do/projeto
    python -m owaspscan app.py --json | jq '.resumo'

Codigos de saida: `0` sem achado de severidade alta, `1` com achado alto,
`2` erro de uso. Candidatos heuristicos (confianca baixa) nao alteram o
codigo de saida — nao seria honesto quebrar um build com base em suposicao.

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

## Calibracao de confianca

O campo `confianca` carrega informacao sobre a cadeia fonte -> sink, nao a
gravidade da CWE:

- **alta**: a fonte alcanca o sink por operacoes de string diretas, em fluxo
  incondicional dentro do escopo.
- **media**: a cadeia passa por funcao nao analisada ou por ramo condicional,
  entao o motor nao viu o caminho inteiro.
- **baixa**: reservada a deteccao heuristica (IDOR), que reporta candidatos.

Sanitizacao nao rebaixa confianca: quando neutraliza a CWE em questao, remove
o achado. Cada sanitizador declara **quais CWEs neutraliza** — `int()` defende
SQL Injection e XSS; `html.escape()` defende XSS e **nao** defende SQL
Injection. Tratar sanitizacao como absoluta seria falso negativo.

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

## Avaliacao

    .venv/bin/python -m owaspscan.metricas tests/amostras

O gabarito mora nas proprias amostras, como comentario na linha do sink:

    cursor.execute("SELECT ... " + ident)   # achado: CWE-89, CWE-639
    cursor.execute(consulta)                # limitacao: CWE-89 fluxo interprocedural

`achado` marca vulnerabilidade que a ferramenta deve encontrar; `limitacao`
marca vulnerabilidade real que sabemos nao encontrar. **Limitacao declarada
conta como falso negativo**: declarar a falha nao a transforma em acerto, e
por isso o recall de CWE-89 e menor que 1.

Resultado atual sobre o corpus (7 arquivos analisados, 1 com erro de sintaxe
proposital): precisao 1.00, recall 0.95, F1 0.97 no geral; o unico falso
negativo e a limitacao interprocedural declarada.

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
