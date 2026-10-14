# AEGIS - site

Interface web (React + Vite + Tailwind) do OWASP-Scan. As análises são feitas
pela API em [`TOOL/owaspscan/api.py`](../TOOL/owaspscan/api.py) (`POST /analisar`).

## Rodar em desenvolvimento

1. Backend, em um terminal:

   ```bash
   cd TOOL
   .venv/bin/python -m pip install -e ".[api]"
   .venv/bin/python -m owaspscan.api        # http://127.0.0.1:8000
   ```

2. Site, em outro terminal (Node.js 20+):

   ```bash
   cd frontend
   npm install
   npm run dev                              # http://localhost:5173
   ```

O Vite repassa `/api/*` para `http://127.0.0.1:8000` (veja `vite.config.js`),
então não precisa configurar CORS. Para apontar para outra API em
desenvolvimento: `OWASPSCAN_API=http://host:porta npm run dev`.

## Build de produção

```bash
VITE_API_URL=https://endereco-da-api npm run build    # gera dist/
```

Sem `VITE_API_URL`, o site chama `/api`, então o servidor que entrega o `dist/`
precisa repassar `/api` para a API. Se a API estiver em outra origem, libere o
site nela com `OWASPSCAN_ORIGENS=https://endereco-do-site`. Veja `.env.example`.

## Como cada aba usa a API

| Aba | Chamada |
|-----|---------|
| FICHEIRO | `multipart/form-data`, um campo `arquivos` por arquivo |
| CÓDIGO | JSON `{"codigo": "...", "nome": "codigo.py"}` |
| URL | o **navegador** baixa o arquivo (links `github.com/.../blob/...` viram `raw`) e envia o texto como JSON. A API não busca URLs, para não abrir SSRF no servidor. |

O código fica em `src/api.js` (chamadas) e `src/Resultado.jsx` (painel de resultado).

## Testar

Roteiro manual com arquivo vulnerável e resultado esperado:
[`docs/teste/ROTEIRO_DE_TESTE.md`](../docs/teste/ROTEIRO_DE_TESTE.md).

```bash
npm run lint
npm run build
```
