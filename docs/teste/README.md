# Exemplos para testar o AEGIS

Arquivos **propositalmente vulneráveis**, usados para demonstrar e testar a ferramenta.
**Não execute nem publique** estes arquivos como aplicação real.

Para analisar qualquer um deles:

```bash
python aegis.py docs/teste/app_vulneravel.py      # Windows: py aegis.py docs\teste\app_vulneravel.py
```

Ou, no modo guiado (`python aegis.py`), digite `exemplo` para analisar o `app_vulneravel.py`.

## O que cada arquivo contém e o que o AEGIS encontra

Resultados medidos com o extra `[linguagens]` instalado (o `aegis.py` e o notebook já instalam).

| Arquivo | Linguagem | O AEGIS encontra | Fora do escopo do AEGIS (não é detectado) |
| --- | --- | --- | --- |
| [`app_vulneravel.py`](app_vulneravel.py) | Python/Flask | **8 achados**: credencial fixa (CWE-798), SQL Injection (CWE-89), Path Traversal (CWE-22), XSS (CWE-79), Open Redirect (CWE-601) e 3 candidatos a IDOR (CWE-639) | — |
| [`login_sql_injection.py`](login_sql_injection.py) | Python/Flask | SQL Injection no login (CWE-89, alta) + candidatos: CSRF (CWE-352) e login sem limite de tentativas (CWE-307) | — |
| [`calculadora_eval.py`](calculadora_eval.py) | Python/Flask | XSS ao devolver o resultado como HTML (CWE-79) | `eval()` de entrada do usuário (Code Injection, CWE-95) |
| [`credenciais_express.js`](credenciais_express.js) | JavaScript/Express | 2 credenciais fixas (CWE-798) | — |
| [`script_frontend.js`](script_frontend.js) | JavaScript | credencial fixa (CWE-798) | `eval()` (CWE-95), `innerHTML` com parâmetro de função (a origem não é uma fonte reconhecida) e requisição HTTP sem TLS (CWE-319) |

A coluna "fora do escopo" é intencional: mostra, com exemplos, o limite declarado da ferramenta.
A lista completa do que o AEGIS cobre está no [`README.md`](../../README.md#8-o-que-o-aegis-detecta) e em [`TOOL/README.md`](../../TOOL/README.md).

## Roteiro de demonstração

Passo a passo para apresentar a ferramenta, com o resultado esperado de cada etapa:
[`ROTEIRO_DE_DEMONSTRACAO.md`](ROTEIRO_DE_DEMONSTRACAO.md).
