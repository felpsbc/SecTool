# Auditoria da documentação

Auditoria completa da documentação do projeto comparada com o código-fonte real. **Nenhum arquivo foi corrigido** — este documento apenas registra os achados (a correção é a etapa seguinte, `docs/plano-de-correcao.md`).

## Método e limitações

- **Escopo**: `README.md` (raiz) e os 9 documentos criados em `docs/` (arquitetura, estrutura, instalacao, configuracao, API, banco-de-dados, fluxos, seguranca, guia-desenvolvedor), comparados contra `TOOL/owaspscan/`, `TOOL/tests/`, `frontend/`, `pyproject.toml`, `package.json`/`package-lock.json` e histórico git. Documentos pré-existentes (`TOOL/README.md`, `CHANGELOG.md`, templates) foram auditados quanto a informação desatualizada.
- **Verificação estática**: contagem de arquivos/funções/linhas, leitura dos trechos citados, conferência de `arquivo:linha`, imports e links. **Os testes não foram executados** (não há `.venv` no ambiente e dependências não foram instaladas) — afirmações sobre resultado de execução são marcadas como não verificadas.
- Data-base: HEAD `442ffb9`.

## Resumo

| Severidade | Quantidade | Natureza |
| --- | --- | --- |
| CRÍTICO | 0 | — |
| ALTO | 1 | links quebrados no README/guia após renomeação de arquivo |
| MÉDIO | 6 | números incorretos propagados, expectativa de verificação errada, componente não documentado, docs desatualizadas |
| BAIXO | 9 | imprecisões, referências obsoletas, inconsistências cosméticas, ressalvas |

Nenhum endpoint inventado, nenhuma funcionalidade inexistente documentada como real, nenhum comando ou versão incorreta, nenhum arquivo inexistente referenciado (além dos links quebrados A1). Os erros encontrados são de **números/contagens**, **um resultado esperado**, **links** e **atualização**.

---

## ALTO

### A1 — Links quebrados para `docs/SEGURANCA.md` (arquivo renomeado para minúsculas)

- **Documentos**: `README.md:121` · `docs/guia-desenvolvedor.md:182`
- **Trecho**: `[docs/SEGURANCA.md](docs/SEGURANCA.md)` (tabela de documentação do README) e "10. `docs/arquitetura.md`, `docs/estrutura.md`, `docs/API.md`, `docs/SEGURANCA.md`" (guia).
- **Evidência**: `ls docs/` mostra `seguranca.md` (minúsculas); não existe `docs/SEGURANCA.md`. O arquivo foi renomeado após a criação dos links. Em Linux o link quebrado é real (404 no GitHub).
- **Correção necessária**: atualizar as 2 referências para `docs/seguranca.md`. Decidir também o padrão de nomenclatura da pasta (ver B5) — `docs/API.md` segue maiúsculo enquanto todo o resto é minúsculo.

---

## MÉDIO

### M1 — Contagem de testes "~336" incorreta, propagada em 6 documentos e contraditória com tabela própria

- **Documentos**: `README.md:89` · `docs/arquitetura.md:11,250,381` · `docs/estrutura.md:44,323` · `docs/guia-desenvolvedor.md:13,97,149` · `docs/instalacao.md:179`
- **Trecho**: "~336 testes" / "~336 funções `test_*`".
- **Evidência**: `grep -c "def test" TOOL/tests/test_*.py` soma **356** funções; além disso há 42 blocos `@pytest.mark.parametrize` (ex.: `test_api.py:92-99,109`), então a coleta real do pytest é **maior que 356**. Contradição interna: a própria tabela por arquivo de `docs/estrutura.md:325-341` lista contagens que somam 356, enquanto o cabeçalho da seção diz "~336".
- **Correção necessária**: substituir "~336" por "356 funções de teste (a coleta pytest é maior devido a testes parametrizados)" em todos os documentos, ou rodar `pytest --collect-only -q` com dependências instaladas e usar o número exato coletado.

### M2 — "11 módulos de detectores": contagem errada (são 12 arquivos / 10 detectores)

- **Documentos**: `README.md:46` · `docs/arquitetura.md:60,108,186` · `docs/estrutura.md:38,100,264` · `docs/fluxos.md:73` · `docs/guia-desenvolvedor.md:59`
- **Trecho**: "`detectores/` — 11 módulos" (e variantes).
- **Evidência**: `ls TOOL/owaspscan/detectores/` = 12 módulos + `__init__.py` (vazio): `base`, `comum`, `sqli`, `xss`, `idor`, `xxe`, `path_traversal`, `open_redirect`, `csrf`, `autorizacao`, `autenticacao`, `credenciais`. São **10 módulos com detectores** (que somam 15 detectores instanciados em `varredura.detectores_padrao()`, `varredura.py:44-62`) + 2 módulos de apoio. A ficha de `detectores/` em `docs/estrutura.md` lista corretamente os 12 — contradição com a árvore anotada do mesmo documento ("11 módulos").
- **Correção necessária**: padronizar como "10 módulos de detectores + `base`/`comum` (15 detectores registrados na varredura)".

### M3 — `docs/instalacao.md`: resultado esperado errado para a varredura de `tests/amostras/seguro`

- **Documento**: `docs/instalacao.md:196-201` (§11, verificação 2)
- **Trecho**: "a segunda tem seção de achados vazia/sem severidade alta e `exit=0`".
- **Evidência**: as amostras de `seguro/` **produzem achados**: o gabarito de `tests/amostras/seguro/flask_xss.py` rotula 3 achados reais (`# achado: CWE-352` na linha 6, `# achado: CWE-862` na linha 15, `# achado: CWE-601` na linha 36 — open redirect com `severidade="media"`, `detectores/open_redirect.py:128`); demais amostras seguras e `config/.env.example` também geram achados (candidatos e severidade baixa, `detectores/credenciais.py:319`). "Seção de achados vazia" está errado. O `exit=0` é plausível (nenhum achado de severidade alta identificado estaticamente nas amostras seguras), mas **não foi verificado por execução**.
- **Correção necessária**: reescrever o esperado: "relatório com achados de severidade média/baixa e candidatos heurísticos (as amostras são seguras apenas para a CWE que nomeiam — `TOOL/README.md` §Avaliação), e `exit=0` por não haver achado de severidade alta". Idealmente confirmar executando após instalar o ambiente.

### M4 — `owaspscan/__init__.py` não documentado (API pública do pacote)

- **Documento**: `docs/estrutura.md` (fichas de arquivos) — componente ausente
- **Trecho**: o inventário não inclui `TOOL/owaspscan/__init__.py` entre os arquivos fichados.
- **Evidência**: `__init__.py:1-17` não é vazio — define a API pública programática do pacote: reexporta `Achado`, `criar_achado`, `MAPA_CWE_OWASP`, `Varredura`, `executar` e expõe `__version__ = VERSAO`. É o caminho de uso `from owaspscan import executar`, relevante para integração e não mencionado em nenhum documento.
- **Correção necessária**: criar ficha em `docs/estrutura.md` (e menção em `docs/guia-desenvolvedor.md` §5) descrevendo os exports e o `__version__`.

### M5 — `TOOL/README.md` §Estado desatualizado (para na Fase 16; git mostra Fase 19)

- **Documento**: `TOOL/README.md:241-261` (pré-existente; já sinalizado em `docs/arquitetura.md` §Riscos)
- **Trecho**: lista "Fase 0" até "Fase 16" como estado do projeto.
- **Evidência**: `git log` contém os commits `868f999 Fase 18: API HTTP (POST /analisar) com FastAPI`, `68e2b24 Fase 19: API aceita JSON alem de formulario...` e `Fase 17: documentacao da cobertura ampliada e versao 0.2.0`; o código correspondente existe (`api.py`, 229 linhas, 26 testes em `test_api.py`).
- **Correção necessária**: acrescentar Fases 17–19 ao §Estado do `TOOL/README.md`.

### M6 — `CHANGELOG.md` desatualizado

- **Documento**: `CHANGELOG.md` (raiz)
- **Trecho**: única entrada "Sprint 00 - Planejamento: Criação do repositório...".
- **Evidência**: o histórico git registra 10 commits de fases numeradas (Fase 10–19), protótipo inicial, frontend base e 6 commits de documentação — nada disso consta no CHANGELOG, que o próprio documento define como registro "das mudanças relevantes por sprint ou marco avaliativo".
- **Correção necessária**: adicionar entradas resumidas (motor 0.1→0.2 com API HTTP, frontend protótipo, documentação técnica).

---

## BAIXO

### B1 — Referência obsoleta ao commit `a90120a` em 6 documentos

- **Documentos**: `docs/arquitetura.md:3` · `docs/estrutura.md:3` · `docs/instalacao.md` (não) · `docs/configuracao.md:3` · `docs/fluxos.md:3` · `docs/banco-de-dados.md:3` · `docs/seguranca.md:3`
- **Trecho**: "baseado exclusivamente no código (commit `a90120a`)".
- **Evidência**: HEAD atual é `442ffb9` (o próprio `a90120a` era o HEAD quando os documentos foram escritos; depois vieram os commits de docs).
- **Correção necessária**: remover o hash (documentos descrevem estado, não snapshot) ou atualizar com nota "revisado em <data/commit>".

### B2 — `docs/fluxos.md`: "25 `.py`" no corpus (são 26 arquivos; 25 analisados + 1 com erro)

- **Documento**: `docs/fluxos.md:217`
- **Trecho**: "`tests/amostras/` (25 `.py` + 9 de configuração, incluindo 1 com erro de sintaxe proposital)".
- **Evidência**: `find TOOL/tests/amostras -name "*.py" | wc -l` = **26** (11 vulneravel + 13 seguro + 2 analisador). A redação sugere que os 25 incluem o quebrado; na verdade são 26 arquivos, dos quais 25 são analisados com sucesso (`quebrado.py` falha). O `TOOL/README.md:226` ("25 arquivos Python e 9 de configuracao analisados, 1 com erro") é ambíguo no mesmo ponto.
- **Correção necessária**: "26 `.py` (25 analisados + 1 com erro de sintaxe proposital) + 9 de configuração".

### B3 — `docs/estrutura.md`: "9 dos 11 detectores" dependem do catálogo (são 10 de 10)

- **Documento**: `docs/estrutura.md:120` (ficha de `motor/catalogo.py`)
- **Evidência**: os imports (verificados) mostram que **todos os 10** módulos de detectores importam `motor.catalogo` (sqli, xss, idor, xxe, path_traversal, open_redirect, csrf, autorizacao, autenticacao, credenciais), além de `taint`, `estrutura`, `confianca`, `comum` e `varredura`.
- **Correção necessária**: "todos os 10 módulos de detectores".

### B4 — `docs/estrutura.md`: dependentes de `achado.py` incluem `comum.py`, que não o importa

- **Documento**: `docs/estrutura.md:100`
- **Trecho**: "Dependentes: todos os 11 módulos de `detectores/`...".
- **Evidência**: `detectores/comum.py:8-10` importa apenas `catalogo`, `estrutura` e `taint` — não importa `achado`. Quem importa `achado` são `base.py` e os 10 detectores.
- **Correção necessária**: "`detectores/base.py` e os 10 módulos de detectores (`comum.py` não usa `achado`)".

### B5 — Nomenclatura inconsistente em `docs/` (maiúsculas × minúsculas)

- **Evidência**: `docs/API.md` é o único nome em maiúsculas; os demais são minúsculos (`arquitetura.md`, `instalacao.md`, `configuracao.md`, `fluxos.md`, `seguranca.md`, `banco-de-dados.md`, `estrutura.md`, `guia-desenvolvedor.md`). Renomeações já quebraram links uma vez (A1) e exigiram correção de referências cruzadas.
- **Correção necessária**: padronizar (sugestão: tudo minúsculo, `docs/api.md`) e atualizar todas as referências cruzadas de uma vez.

### B6 — "19 fases commitadas": apenas 10 commits nomeados "Fase N" existem

- **Documentos**: `docs/guia-desenvolvedor.md:13` ("19 fases commitadas") · `README.md:113` e `docs/arquitetura.md:11` ("19 fases")
- **Evidência**: `git log` tem commits individuais "Fase 10" a "Fase 19" (10 commits); as Fases 0–9 precedem o commit único `4ee52b3 Adiciona protótipo owaspscan em TOOL/`. O número 19 como *fase atual* está correto; "commitadas" individualmente, não.
- **Correção necessária**: "fases 0–19 (commits individuais da Fase 10 em diante)".

### B7 — Porta padrão do Vite não confirmada por execução

- **Documentos**: `docs/instalacao.md:171` ("padrão http://localhost:5173") · `README.md` ("http://localhost:5173")
- **Evidência**: o `vite.config.js` não define `server.port` — a porta vem do padrão do Vite (historicamente 5173), mas não foi confirmada executando `npm run dev` neste ambiente. **[NECESSÁRIO CONFIRMAR por execução]**
- **Correção necessária**: confirmar rodando o dev server; se diferente, ajustar os dois documentos.

### B8 — Documentos de gestão permanecem como template (lacuna já registrada, formalizada aqui)

- **Documentos**: `docs/requisitos.md`, `docs/decisoes/` (sem nenhum ADR), `docs/reunioes/`, `sprints/sprint-00-planejamento.md`, `entregas/`
- **Evidência**: conteúdo integralmente genérico/institucional apesar de o projeto estar na Fase 19; `docs/arquitetura.md` §"Diagramas e relação com ADRs" recomenda 4 ADRs que não foram criados; o `README.md` raiz antigo vinculava requisitos/arquitetura a esses templates.
- **Correção necessária**: preencher `docs/requisitos.md` e criar ao menos os ADRs recomendados (etapa de conteúdo, não de código).

### B9 — Verificações por execução não realizadas nesta auditoria

- **Documentos afetados**: `docs/instalacao.md` §11 (todos os "Esperado:"), métricas declaradas (`precisão 1.00 / recall 0.98 / F1 0.99` — repetidas em `README.md`, `docs/arquitetura.md`, `docs/fluxos.md`, `docs/instalacao.md`).
- **Evidência**: sem `.venv`/`node_modules` no ambiente da auditoria, não se executou `pytest`, `owaspscan` nem `metricas`. Os valores vêm do `TOOL/README.md` §Avaliação (declarados pelo projeto) e da leitura estática do código — coerentes, porém não reconfirmados.
- **Correção necessária**: nenhuma imediata; ao instalar o ambiente (etapa de validação), executar os 5 passos de `docs/instalacao.md` §11 e ajustar os "Esperado:" se divergirem.

---

## Verificações realizadas sem divergências

Confirmados como corretos na auditoria (amostra representativa):

- **Endpoints**: `GET /saude` e `POST /analisar` são os únicos registrados em `api.py` — nenhum endpoint inventado nem ausente na documentação; `/docs`, `/redoc`, `/openapi.json` são rotas automáticas do FastAPI (sem override de `docs_url`/`redoc_url`); OPTIONS via `CORSMiddleware`.
- **Contratos da API**: limites 50 arquivos/1 MB (`api.py:40-41`), códigos 400/413/415/422 e mensagens, `raiz="envio"`, `allow_methods=["GET","POST"]`, `allow_credentials` padrão False — todos conferem com o código e com `test_api.py`.
- **Versões e dependências**: `owaspscan 0.2.0` (pyproject + `varredura.VERSAO`), `requires-python >=3.11`, extras `api`/`dev` com pisos corretos; React ^19.2.8, Vite ^8.3.0 (lock: 8.3.1), Tailwind ^3.4.19, Node `^20.19.0 || >=22.12.0` (engines do Vite no lockfile), `lockfileVersion: 3`.
- **Variáveis de ambiente**: exatamente 3 (`OWASPSCAN_HOST/PORTA/ORIGENS`), somente em `api.py:46,223-224`; nenhum `.env` no projeto; frontend sem `VITE_*`.
- **Referências `arquivo:linha`** (verificação por amostragem ampla): `cli.py:52/56-58/71`, `varredura.py:44-62/92`, `api.py:75/98/123-130/133/144/164/191/200/218`, `relatorio.py:25/50/103/167`, `achado.py:116-127/149-172/180`, `analisador.py:35/98/112/154`, `taint.py:281/310-328`, `motor/credenciais.py:246`, `App.jsx:33/47-62/78-84/98-102/269-294`, `detectores/open_redirect.py:128` — todas conferem.
- **Comandos**: todos os comandos documentados existem e batem com `TOOL/README.md`/`pyproject.toml`/`package.json` (`python -m owaspscan`, `--json`, `--versao`, `python -m owaspscan.api`, `python -m owaspscan.metricas`, `pytest`, `npm run dev/build/lint/preview`, `pip install -e ".[dev]"/".[api]"/".[dev,api]"`).
- **Ausências documentadas**: sem banco, sem auth/rate limit, sem CI/Docker, sem logs próprios, sem `fetch` no frontend, sem `eval`/`exec`/`dangerouslySetInnerHTML` — todas reconfirmadas por varredura.
- **Severidades dos detectores** citadas em exemplos (SQLi `alta`, open redirect `media`, XSS `media`, IDOR `media` candidato, `.env.example` `baixa`) — conferem com o código.
- **Contagens por arquivo de teste** na tabela de `docs/estrutura.md` — conferem com `grep -c "def test"` (a soma é que contradiz o "~336", ver M1).
- **Links internos**: todos os links de `README.md` e referências cruzadas de `docs/` resolvem para arquivos existentes, exceto os 2 apontados em A1.

## Observações finais

1. Não houve achado de **informação inventada**: os documentos separam explicitamente o que existe do que é protótipo/previsto (frontend, pre-commit, textos fictícios do site), o que a auditoria reconfirmou.
2. A causa raiz de A1/B5 é a **renomeação manual de arquivos** sem atualização das referências — recomenda-se padronizar nomenclatura antes da etapa de correção.
3. A causa raiz de M1/M2/B2/B3/B4 é **contagem aproximada escrita antes da verificação final** — todos os casos têm correção mecânica.
4. Prioridade sugerida para a correção (etapa 14): A1 → M3 → M1/M2 → M4 → M5/M6 → B1–B9.
