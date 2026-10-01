// Cliente da API do OWASP-Scan (TOOL/owaspscan/api.py).
// Em desenvolvimento o Vite repassa /api para http://127.0.0.1:8000
// (vite.config.js). Em producao, defina VITE_API_URL com a URL da API.
const BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '');

async function enviar(corpo, cabecalhos = {}) {
  let resposta;
  try {
    resposta = await fetch(`${BASE}/analisar`, { method: 'POST', headers: cabecalhos, body: corpo });
  } catch {
    throw new Error('sem_conexao');
  }
  const dados = await resposta.json().catch(() => null);
  if (!resposta.ok) {
    // HTTPException devolve {"detail": "..."}; erro de validacao, uma lista
    const detalhe = dados?.detail;
    throw new Error(typeof detalhe === 'string' ? detalhe : `HTTP ${resposta.status}`);
  }
  return dados;
}

export function analisarArquivos(arquivos) {
  const formulario = new FormData();
  arquivos.forEach((arquivo) => formulario.append('arquivos', arquivo, arquivo.name));
  return enviar(formulario);
}

export function analisarCodigo(codigo, nome = 'codigo.py') {
  return enviar(JSON.stringify({ codigo, nome }), { 'Content-Type': 'application/json' });
}

// Link "blob" do GitHub aponta para a pagina HTML; o conteudo esta no raw.
function urlDoConteudo(url) {
  const github = url.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
  return github ? `https://raw.githubusercontent.com/${github[1]}/${github[2]}/${github[3]}` : url;
}

// A API nao busca URLs (evita SSRF no servidor): o navegador baixa o
// arquivo e envia o texto como codigo colado.
export async function analisarUrl(url) {
  const endereco = urlDoConteudo(url.trim());
  let resposta;
  try {
    resposta = await fetch(endereco);
  } catch {
    throw new Error('url_inacessivel');
  }
  if (!resposta.ok) throw new Error('url_inacessivel');
  const nome = new URL(endereco).pathname.split('/').pop() || 'codigo.py';
  return analisarCodigo(await resposta.text(), nome);
}
