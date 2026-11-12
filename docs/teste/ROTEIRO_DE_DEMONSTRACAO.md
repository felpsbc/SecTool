# Roteiro de demonstração

Passo a passo para apresentar o AEGIS e conferir que o resultado é o esperado.
Arquivo usado: [`app_vulneravel.py`](app_vulneravel.py), um app Flask **propositalmente vulnerável**
(não rode esse app; ele serve só para ser analisado). Outros exemplos: [`README.md`](README.md).

Duração sugerida: 5 a 7 minutos. Faça o passo 0 **antes** da apresentação.

## 0. Preparação (na véspera)

Na pasta do repositório:

```bash
python aegis.py --testar        # Windows: py aegis.py --testar
```

Isso instala o ambiente (só na primeira vez, precisa de internet) e confirma que tudo funciona.
Depois disso, os passos 2 e 3 funcionam **sem internet**.

## 1. O problema (1 min)

40–45% do código gerado por IA contém vulnerabilidades conhecidas (Pearce, 2022; Veracode, 2025),
e esse código costuma ir para produção sem revisão (Perry, 2023). Referência: [`README.md`](../../README.md#problema-e-objetivo).

## 2. Análise ao vivo (2 min)

| # | Ação | Resultado esperado |
| --- | --- | --- |
| D1 | `python aegis.py` e digitar `exemplo` | Resumo com **8 achados** (alta 3, média 5; 3 candidatos) — tabela da seção 5 |
| D2 | Mostrar o SQL Injection da linha 24 e a seção **RECOMENDACOES POR TIPO** no fim do relatório | Explicação do problema e correção (query parametrizada) |
| D3 | Arrastar para a janela a pasta de um projeto real (ou `docs/teste/`) | Relatório do projeto inteiro, salvo em `relatorio_aegis.txt` |

## 3. Prova de que funciona (1 min)

| # | Ação | Resultado esperado |
| --- | --- | --- |
| D4 | `python aegis.py --testar` | Linha `geral`: **precisão 1.00, recall 0.97, F1 0.98** no corpus rotulado |
| D5 | Explicar a nota no fim da tabela | O corpus é próprio: mede consistência interna, não generalização (honestidade científica) |

## 4. A plateia participa (2 min)

| # | Ação | Resultado esperado |
| --- | --- | --- |
| D6 | Abrir o notebook no Colab ([link](https://colab.research.google.com/github/felpsbc/SecTool/blob/main/AEGIS.ipynb)) e clicar no ▶ da primeira célula | Aparece a caixa para colar código (cerca de 1 min na primeira vez) |
| D7 | Clicar em **Usar um exemplo vulnerável** → **Analisar** | Os mesmos 8 achados, em cartões com "Problema" e "Como corrigir" |
| D8 | Colar o trecho seguro abaixo → **Analisar** | "✅ Nenhuma vulnerabilidade encontrada pelos detectores do AEGIS" |
| D9 | Na célula *Analisar um projeto inteiro*, colar o link do GitHub de alguém da plateia | Relatório do repositório |

Trecho seguro para o D8 (consulta parametrizada):

```python
import sqlite3
from flask import request

def buscar():
    termo = request.args.get("q")
    sqlite3.connect("x.db").execute("SELECT * FROM t WHERE nome = ?", (termo,))
```

> Plano B sem internet: os passos D1 a D5 funcionam offline depois do passo 0. Vale ter também um vídeo curto gravado.

## 5. Achados esperados em `app_vulneravel.py`

| Linha | CWE | Vulnerabilidade | OWASP | Severidade | Confiança |
|------:|-----|-----------------|-------|------------|-----------|
| 12 | CWE-798 | Hard-coded Credentials | A07:2021 | alta | alta |
| 24 | CWE-89 | SQL Injection | A03:2021 | alta | alta |
| 45 | CWE-22 | Path Traversal | A01:2021 | alta | alta |
| 32 | CWE-79 | Cross-Site Scripting | A03:2021 | média | alta |
| 38 | CWE-601 | Open Redirect | A01:2021 | média | alta |
| 24 | CWE-639 | IDOR (candidato) | A01:2021 | média | **baixa** |
| 52 | CWE-639 | IDOR (candidato) | A01:2021 | média | **baixa** |
| 61 | CWE-639 | IDOR (candidato) | A01:2021 | média | **baixa** |

Pontos para comentar:

- **Controle negativo:** a rota `/produto-seguro` (linha 61) usa query parametrizada e **não** gera
  SQL Injection. Ela aparece só como candidato a IDOR, porque busca por id sem filtrar pelo dono.
  Num catálogo de produtos isso é legítimo — por isso IDOR é heurístico e pede revisão manual.
- Candidatos aparecem separados dos achados rastreados por taint e nunca com confiança maior que "baixa".
- O segredo da linha 12 é exibido mascarado (`"se***"`): o relatório não repete a credencial.

## 6. Teste automático equivalente

A tabela da seção 5 também é verificada pelo pytest (`TOOL/tests/test_documento_teste.py`).
Se o motor mudar e o teste falhar, atualize esta tabela junto.

```bash
cd TOOL && .venv/bin/python -m pytest tests/test_documento_teste.py -v
```

A mesma análise pela API HTTP (com `python aegis.py --api` rodando em outro terminal):

```bash
curl -F arquivos=@docs/teste/app_vulneravel.py http://127.0.0.1:8000/analisar
```

## Registro de execução

| Data | Quem | D1–D3 | D4–D5 | D6–D9 | Observações |
|------|------|-------|-------|-------|-------------|
| | | | | | |
