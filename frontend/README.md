# AEGIS — site de demonstração

Interface web do AEGIS (React 19 + Vite 8 + Tailwind CSS 3), publicada em
<https://aegisscan-zeta.vercel.app/>.

> **Estado atual:** o site apresenta a interface do produto e faz uma análise
> **simplificada no próprio navegador** (regras em `src/App.jsx`). Ele **não chama**
> o motor `owaspscan` nem a API. Para o resultado completo use o notebook Colab ou o
> `aegis.py` — veja o [`README.md`](../README.md) da raiz.

## Rodar em desenvolvimento

Requer **Node.js ^20.19.0 ou ≥22.12.0**.

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

## Build e verificação

```bash
npm run lint
npm run build        # gera dist/ (o mesmo build que a Vercel publica)
```

## Ligar o site à API (pronto, ainda não aplicado)

O cliente da API já existe e está pronto, mas não está importado pelo `App.jsx`:

| Arquivo | Papel |
| --- | --- |
| `src/api.js` | envia arquivos (multipart), código colado (JSON) ou URL para `POST /analisar` |
| `src/Resultado.jsx` | painel de resultado no estilo da interface |
| `vite.config.js` | em desenvolvimento, repassa `/api/*` para `http://127.0.0.1:8000` |
| `.env.example` | `VITE_API_URL`, endereço da API em produção |

Passo a passo para reconectar (código, Vercel e API): [`docs/deploy.md`](../docs/deploy.md), Apêndice D.
Arquivos de exemplo para testar uploads: [`docs/teste/`](../docs/teste/README.md).
