# Roteiro de teste: site AEGIS + API do OWASP-Scan

Roteiro para conferir, pelo navegador, se o site (`frontend/`) está ligado à
API (`TOOL/owaspscan/api.py`) e se o resultado mostrado é o esperado.

Arquivo de teste: [`app_vulneravel.py`](app_vulneravel.py), um app Flask
**propositalmente vulnerável**. Não rode esse app; ele serve só para ser analisado.

## 1. Subir o backend

```bash
cd TOOL
python -m venv .venv
.venv/bin/python -m pip install -e ".[api,dev]"
.venv/bin/python -m owaspscan.api          # http://127.0.0.1:8000/docs
```

Conferência: <http://127.0.0.1:8000/saude> responde `{"status":"ok","versao":"0.2.0"}`.

## 2. Subir o site

Em outro terminal (precisa de Node.js 20+):

```bash
cd frontend
npm install
npm run dev                                # http://localhost:5173
```

Em desenvolvimento, o Vite repassa `/api/*` para `http://127.0.0.1:8000`, então
não é preciso configurar CORS. Se a API estiver em outro endereço, use
`OWASPSCAN_API=http://host:porta npm run dev`.

## 3. Casos de teste

| # | Aba | Ação | Resultado esperado |
|---|-----|------|--------------------|
| T1 | FICHEIRO | Escolher `docs/teste/app_vulneravel.py` e clicar em **Confirmar upload** | Painel "Resultado da análise" com **8 achados**: Alta 3, Média 5, Candidatos 3 (detalhes na tabela abaixo) |
| T2 | CÓDIGO | Colar o conteúdo de `app_vulneravel.py` e clicar em **Analisar** | Os mesmos 8 achados, com o arquivo exibido como `codigo.py` |
| T3 | CÓDIGO | Colar o trecho seguro abaixo e clicar em **Analisar** | "Nenhuma vulnerabilidade encontrada" |
| T4 | URL | Colar o link de um `.py` público no GitHub (`github.com/.../blob/...`) e clicar em **Pesquisar** | O navegador baixa o arquivo (o link é convertido para `raw`) e o resultado aparece |
| T5 | FICHEIRO | Enviar um `.txt` | Mensagem vermelha: "tipo de arquivo nao suportado ... (aceitos: .py e configuracao ...)" |
| T6 | qualquer | Parar o backend (Ctrl+C) e analisar de novo | Mensagem vermelha: "Não foi possível ligar à API..." |
| T7 | — | Alternar idioma (PT/EN) e tema (claro/escuro) com um resultado na tela | Os textos do painel mudam de idioma e as cores acompanham o tema |

Trecho seguro para o T3:

```python
import sqlite3
from flask import request

def buscar():
    termo = request.args.get("q")
    sqlite3.connect("x.db").execute("SELECT * FROM t WHERE nome = ?", (termo,))
```

## 4. Achados esperados no T1

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

Pontos a observar:

- **Controle negativo:** a rota `/produto-seguro` (linha 61) usa query
  parametrizada e **não** gera SQL Injection. Ela aparece só como candidato a
  IDOR, porque busca por id sem filtrar pelo dono. Num catálogo de produtos
  isso é legítimo, o que mostra por que IDOR é heurístico e precisa de
  revisão manual.
- Candidatos a IDOR aparecem na seção **Candidatos**, separados dos achados
  rastreados por taint, e nunca com confiança maior que "baixa".
- O segredo na linha 12 é exibido mascarado (`"se***"`): o relatório não
  repete a credencial.

## 5. Teste automático equivalente

A tabela da seção 4 também é verificada pelo pytest
(`TOOL/tests/test_documento_teste.py`). Se o motor mudar e o teste falhar,
atualize esta tabela junto.

```bash
cd TOOL && .venv/bin/python -m pytest tests/test_documento_teste.py -v
```

Sem navegador, a mesma chamada que o site faz pode ser testada com curl:

```bash
curl -F arquivos=@docs/teste/app_vulneravel.py http://127.0.0.1:8000/analisar
```

## Registro de execução

| Data | Quem | T1 | T2 | T3 | T4 | T5 | T6 | T7 | Observações |
|------|------|----|----|----|----|----|----|----|-------------|
| | | | | | | | | | |
