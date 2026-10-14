import { useState, useEffect, useRef } from 'react';
import { traducoes } from './translate';
import { analisarArquivos, analisarCodigo, analisarUrl } from './api';
import Resultado from './Resultado';

// Ícones minimalistas
const SunIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
);
const MoonIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
);
const TerminalIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
);
const DownloadIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
);
const FileCheckIcon = () => (
  <svg className="w-12 h-12 text-blue-500 dark:text-green-500 mb-4" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
);

// Ícone "A" corporativo
const AIcon = ({ size = "normal" }) => {
  const isLarge = size === "large";
  return (
    <div className={`flex items-center justify-center rounded-xl bg-gradient-to-b from-blue-500 to-blue-700 dark:from-green-500 dark:to-green-700 text-white font-bold shadow-sm border-t border-white/20 ${isLarge ? 'w-14 h-14 text-4xl mr-3' : 'w-9 h-9 text-xl'}`}>
      A
    </div>
  );
};

// Linguagem do codigo colado: a API decide o analisador pela extensao do nome.
const LINGUAGENS = [
  ['.py', 'Python'],
  ['.js', 'JavaScript'],
  ['.ts', 'TypeScript'],
  ['.java', 'Java'],
  ['.php', 'PHP'],
  ['.html', 'HTML'],
];

function App() {
  const [idioma, setIdioma] = useState('pt');
  const [tema, setTema] = useState(() => localStorage.getItem('aegis-tema') || 'dark');
  const [abaAtiva, setAbaAtiva] = useState('file');
  
  // ESTADO DE NAVEGAÇÃO DE PÁGINAS (Novo)
  const [paginaAtual, setPaginaAtual] = useState('home');
  
  // ESTADOS DOS ARQUIVOS
  const [arquivos, setArquivos] = useState([]);
  const [arrastando, setArrastando] = useState(false);
  const fileInputRef = useRef(null);

  // ESTADOS DA ANÁLISE (API)
  const [codigo, setCodigo] = useState('');
  const [extensao, setExtensao] = useState('.py');
  const [url, setUrl] = useState('');
  const [carregando, setCarregando] = useState(false);
  const [resultado, setResultado] = useState(null);
  const [erro, setErro] = useState('');
  
  const t = traducoes[idioma];

  // Controle de Tema
  useEffect(() => {
    const root = document.documentElement;
    const metaThemeColor = document.getElementById('meta-theme-color');

    if (tema === 'dark') {
      root.classList.add('dark');
      root.style.colorScheme = 'dark';
      if (metaThemeColor) metaThemeColor.setAttribute('content', '#0f172a');
    } else {
      root.classList.remove('dark');
      root.style.colorScheme = 'light';
      if (metaThemeColor) metaThemeColor.setAttribute('content', '#f8fafc');
    }
    
    localStorage.setItem('aegis-tema', tema);
  }, [tema]);

  const alternarTema = () => setTema(tema === 'dark' ? 'light' : 'dark');
  const alternarIdioma = () => setIdioma(idioma === 'pt' ? 'en' : 'pt');

  // FUNÇÕES DE ARRASTAR E SOLTAR (Drag & Drop)
  const handleDragOver = (e) => {
    e.preventDefault();
    setArrastando(true);
  };
  
  const handleDragLeave = (e) => {
    e.preventDefault();
    setArrastando(false);
  };
  
  const handleDrop = (e) => {
    e.preventDefault();
    setArrastando(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setArquivos((prev) => [...prev, ...Array.from(e.dataTransfer.files)]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setArquivos((prev) => [...prev, ...Array.from(e.target.files)]);
    }
  };

  const removerArquivo = (e, indexParaRemover) => {
    e.stopPropagation();
    setArquivos((prev) => prev.filter((_, index) => index !== indexParaRemover));
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // Chama a API e guarda o resultado (ou a mensagem de erro) para o painel
  const analisar = async (e, chamada) => {
    e?.stopPropagation();
    if (carregando) return;
    setCarregando(true);
    setErro('');
    setResultado(null);
    try {
      setResultado(await chamada());
    } catch (falha) {
      const mensagens = { sem_conexao: t.err_no_connection, url_inacessivel: t.err_url };
      setErro(mensagens[falha.message] || `${t.err_prefix} ${falha.message}`);
    } finally {
      setCarregando(false);
    }
  };

  const analisarUpload = (e) => analisar(e, () => analisarArquivos(arquivos));
  const analisarSnippet = (e) => codigo.trim() ? analisar(e, () => analisarCodigo(codigo, `codigo${extensao}`)) : setErro(t.err_empty);
  const analisarLink = (e) => url.trim() ? analisar(e, () => analisarUrl(url)) : setErro(t.err_empty);

  const navegarPara = (e, pagina) => {
    e.preventDefault();
    setPaginaAtual(pagina);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // RENDERIZADOR DE CONTEÚDO (Home vs Páginas Secundárias)
  const renderizarConteudo = () => {
    if (paginaAtual === 'home') {
      return (
        <>
          {/* LOGO CENTRAL E TEXTO */}
          <div className="text-center mb-10 flex flex-col items-center animate-fade-in">
            <div className="flex items-center justify-center mb-6">
              <AIcon size="large" />
              <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                AEGIS
              </h1>
            </div>
            <p className="text-sm md:text-base text-slate-500 dark:text-slate-400 max-w-xl font-medium leading-relaxed">
              {t.subtitle}
            </p>
          </div>

          {/* PAINEL DE ANÁLISE */}
          <div className="w-full max-w-3xl bg-white dark:bg-[#151e32] rounded-xl shadow-sm border border-slate-200 dark:border-slate-800/80 overflow-hidden animate-fade-in">
            {/* ABAS CENTRALIZADAS */}
            <div className="relative flex items-center justify-center bg-slate-50/50 dark:bg-[#0f172a]/50 border-b border-slate-200 dark:border-slate-800 pt-2 px-4">
              <div className="flex gap-4 md:gap-8">
                {[
                  { id: 'file', label: t.tab_file },
                  { id: 'url', label: t.tab_url },
                  { id: 'snippet', label: t.tab_snippet }
                ].map((aba) => (
                  <button
                    key={aba.id}
                    onClick={() => setAbaAtiva(aba.id)}
                    className={`px-4 py-4 text-xs font-bold tracking-wider uppercase border-b-2 transition-colors ${
                      abaAtiva === aba.id
                        ? 'text-blue-600 dark:text-green-500 border-blue-600 dark:border-green-500'
                        : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 border-transparent'
                    }`}
                  >
                    {aba.label}
                  </button>
                ))}
              </div>

              <div className="absolute right-4 bottom-3 hidden sm:block">
                <button 
                  onClick={() => setAbaAtiva('cli')} 
                  className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold border transition-colors ${
                    abaAtiva === 'cli'
                      ? 'bg-blue-50 dark:bg-green-900/20 border-blue-200 dark:border-green-800 text-blue-700 dark:text-green-400'
                      : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-700'
                  }`}
                >
                  <TerminalIcon />
                  <span>CLI</span>
                </button>
              </div>
            </div>

            {/* ÁREAS DE CONTEÚDO */}
            <div className="p-8 md:p-12 min-h-[300px] flex flex-col justify-center items-center">
              {abaAtiva === 'file' && (
                <div 
                  className={`w-full h-auto min-h-[192px] border-2 border-dashed rounded-xl flex flex-col items-center justify-center transition-colors p-6
                    ${arrastando 
                      ? 'border-blue-500 bg-blue-50 dark:border-green-500 dark:bg-green-900/20' 
                      : 'border-slate-300 dark:border-slate-600/60 bg-slate-50/50 hover:bg-slate-100 dark:bg-[#0f172a]/30 dark:hover:bg-[#0f172a]/80'
                    }
                    ${arquivos.length > 0 ? 'border-solid border-transparent dark:border-transparent bg-transparent hover:bg-transparent dark:hover:bg-transparent' : 'cursor-pointer'}
                  `}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => arquivos.length === 0 && fileInputRef.current?.click()}
                >
                  <input type="file" ref={fileInputRef} className="hidden" multiple onChange={handleFileChange} />

                  {arquivos.length === 0 ? (
                    <>
                      <svg className="w-10 h-10 text-slate-400 mb-4 pointer-events-none" fill="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm-1 2.5L18.5 9H13V4.5zM6 20V4h5v7h7v9H6z"/></svg>
                      <button className="bg-white dark:bg-[#1e293b] border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:text-blue-600 dark:hover:text-green-400 px-8 py-2.5 rounded-lg text-sm font-semibold shadow-sm pointer-events-none transition-colors">
                        {t.btn_choose}
                      </button>
                      <span className="text-xs text-slate-400 mt-3 pointer-events-none">
                        {idioma === 'pt' ? 'ou arraste e solte o ficheiro aqui' : 'or drag and drop file here'}
                      </span>
                    </>
                  ) : (
                    <div className="flex flex-col items-center w-full">
                      <FileCheckIcon />
                      <div className="flex flex-wrap justify-center gap-2 mb-6 max-h-32 overflow-y-auto w-full px-2">
                        {arquivos.map((arquivo, index) => (
                          <div key={index} className="flex items-center gap-2 bg-slate-200 dark:bg-[#1e293b] border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 px-3 py-1.5 rounded-md text-xs font-medium shadow-sm">
                            <span className="truncate max-w-[150px]" title={arquivo.name}>{arquivo.name}</span>
                            <button onClick={(e) => removerArquivo(e, index)} className="hover:text-red-500 transition-colors">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                            </button>
                          </div>
                        ))}
                      </div>
                      <div className="flex gap-4">
                        <button onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }} className="bg-transparent border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 px-5 py-2.5 rounded-lg text-sm font-semibold transition-colors">
                          + {idioma === 'pt' ? 'Mais' : 'More'}
                        </button>
                        <button onClick={analisarUpload} disabled={carregando} className="bg-transparent border border-blue-600 dark:border-green-600 text-blue-600 dark:text-green-500 hover:bg-blue-600 hover:text-white dark:hover:bg-green-600 dark:hover:text-white px-8 py-2.5 rounded-lg text-sm font-semibold transition-colors">
                          {carregando ? t.analyzing : (idioma === 'pt' ? 'Confirmar upload' : 'Confirm upload')}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {abaAtiva === 'url' && (
                <div className="w-full max-w-xl flex flex-col gap-4">
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    </div>
                    <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && analisarLink(e)} placeholder={t.url_placeholder} className="w-full bg-slate-50 dark:bg-[#0f172a] border border-slate-300 dark:border-slate-700 rounded-lg py-3.5 pl-12 pr-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-green-500 focus:border-transparent transition-all shadow-inner" />
                  </div>
                  <button onClick={analisarLink} disabled={carregando} className="w-full bg-blue-600 hover:bg-blue-700 dark:bg-green-600 dark:hover:bg-green-700 text-white py-3.5 rounded-lg text-sm font-bold shadow-sm transition-colors">
                    {carregando ? t.analyzing : t.btn_search}
                  </button>
                </div>
              )}

              {abaAtiva === 'snippet' && (
                <div className="w-full flex flex-col gap-4">
                  <select value={extensao} onChange={(e) => setExtensao(e.target.value)} aria-label={t.snippet_language} className="self-start bg-slate-50 dark:bg-[#0f172a] border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:focus:ring-green-500">
                    {LINGUAGENS.map(([valor, rotulo]) => <option key={valor} value={valor}>{rotulo}</option>)}
                  </select>
                  <textarea value={codigo} onChange={(e) => setCodigo(e.target.value)} className="w-full h-48 bg-slate-50 dark:bg-[#0b1120] text-slate-800 dark:text-green-400 border border-slate-300 dark:border-slate-700 rounded-lg p-5 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 dark:focus:ring-green-500 resize-none shadow-inner" placeholder={t.snippet_placeholder} spellCheck="false" />
                  <button onClick={analisarSnippet} disabled={carregando} className="self-end bg-blue-600 hover:bg-blue-700 dark:bg-green-600 dark:hover:bg-green-700 text-white px-10 py-2.5 rounded-lg text-sm font-bold shadow-sm transition-colors">
                    {carregando ? t.analyzing : t.btn_scan}
                  </button>
                </div>
              )}

              {abaAtiva === 'cli' && (
                <div className="w-full flex flex-col items-center text-center">
                  <div className="mb-5 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-full border border-slate-200 dark:border-slate-700">
                    <TerminalIcon className="w-6 h-6 text-slate-600 dark:text-slate-400" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">{t.cli_title}</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-8 max-w-sm">{t.cli_desc}</p>
                  <div className="flex flex-col sm:flex-row gap-3 w-full max-w-md">
                    <div className="flex-grow bg-slate-100 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-300 font-mono text-sm p-3 rounded-lg shadow-inner flex items-center justify-center">
                      <code>npm install -g @aegis/cli</code>
                    </div>
                    <button className="flex items-center justify-center gap-2 bg-slate-800 hover:bg-slate-900 dark:bg-slate-200 dark:hover:bg-white text-white dark:text-slate-900 px-6 py-3 rounded-lg text-sm font-bold shadow-sm transition-colors">
                      <DownloadIcon />
                      Baixar
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {erro && (
            <div className="w-full max-w-3xl mt-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 rounded-xl px-6 py-4 text-sm">
              {erro}
            </div>
          )}

          {resultado && <Resultado resultado={resultado} t={t} />}

          <div className="w-full max-w-2xl text-center mt-6 mb-12 px-4">
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              {t.disclaimer_text} <a href="#" onClick={(e) => navegarPara(e, 'termos')} className="text-blue-600 dark:text-blue-400 hover:underline font-semibold">{t.learn_more}</a>
            </p>
          </div>
        </>
      );
    }

    // CONTEÚDOS DAS PÁGINAS ESTÁTICAS
    const conteudosPagina = {
      docs_official: {
        titulo: t.ft_docs_official,
        corpo: "Bem-vindo à documentação oficial do AEGIS.\n\nO motor de análise estática AEGIS foi desenhado para integrar de forma fluida nas pipelines CI/CD modernas, garantindo a detecção de vulnerabilidades OWASP Top 10 em tempo real.\n\n### Arquitetura\nO AEGIS divide-se no Scanner web e na nossa poderosa CLI, permitindo auditorias locais e remotas."
      },
      termos: {
        titulo: t.ft_terms,
        corpo: "Termos de Uso do AEGIS.\n\n1. Aceitação dos Termos\nAo utilizar os nossos serviços, o utilizador concorda com as políticas estabelecidas neste documento.\n\n2. Limitações Técnicas\nO AEGIS é fornecido 'no estado em que se encontra'. O motor estático não executa código malicioso submetido, apenas o examina analiticamente."
      },
      privacidade: {
        titulo: t.ft_privacy,
        corpo: "Política de Privacidade.\n\nNo AEGIS, valorizamos profundamente a sua privacidade. Os arquivos enviados para a plataforma através do painel Web são processados de forma efémera na memória. Não armazenamos o código fonte após a conclusão da análise, a menos que opte explicitamente por colaborar com a comunidade enviando apenas hashes."
      },
      como_usar: {
        titulo: t.ft_how_to,
        corpo: "Como iniciar a sua primeira análise com o AEGIS:\n\nPasso 1: Selecione a aba correspondente ao que deseja testar (Ficheiro, URL ou Código-fonte).\nPasso 2: Efetue o upload ou cole a sua string de dados.\nPasso 3: Clique em 'Analisar' e aguarde o relatório dinâmico detalhando o nível de risco, linhas afetadas e recomendações de mitigação."
      },
      faq: {
        titulo: t.ft_faq,
        corpo: "Perguntas Frequentes (FAQ)\n\n• O AEGIS é gratuito?\nSim, o uso comunitário web é inteiramente gratuito.\n\n• Que linguagens são suportadas no Snippet?\nNeste momento, o nosso motor SAST suporta Python, JavaScript/TypeScript, Java, PHP e HTML.\n\n• Posso apagar os meus relatórios?\nPor padrão, não gravamos dados persistentes, mas utilizadores autenticados terão total controlo sobre o histórico de auditorias."
      },
      scripts: {
        titulo: t.ft_scripts,
        corpo: "Integração via Scripts de API.\n\nA mesma análise do site está disponível por HTTP.\nEndpoint: POST http://127.0.0.1:8000/analisar (documentação interativa em /docs)\n\nExemplo em Python (Requests):\n```python\nimport requests\n\nurl = 'http://127.0.0.1:8000/analisar'\nfiles = [('arquivos', open('app.py', 'rb'))]\n\nresponse = requests.post(url, files=files)\nprint(response.json()['resumo'])\n```\n\nTambém aceita JSON: {\"codigo\": \"...\", \"nome\": \"app.py\"}"
      }
    };

    const pagina = conteudosPagina[paginaAtual];

    if (!pagina) return null;

    return (
      <div className="w-full max-w-4xl bg-white dark:bg-[#151e32] rounded-xl shadow-sm border border-slate-200 dark:border-slate-800/80 p-8 md:p-14 text-left animate-fade-in mb-12">
        <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white mb-6 pb-6 border-b border-slate-200 dark:border-slate-800">
          {pagina.titulo}
        </h2>
        <div className="text-slate-600 dark:text-slate-400 whitespace-pre-wrap leading-relaxed space-y-4">
          {/* O split permite tratar quebras de linha e renderizar pequenos blocos de código */}
          {pagina.corpo.split('\n').map((linha, i) => (
            <p key={i} className={linha.startsWith('###') ? 'text-lg font-bold text-slate-800 dark:text-white mt-6 mb-2' : ''}>
              {linha.replace('### ', '')}
            </p>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0f172a] text-slate-800 dark:text-slate-200 font-sans flex flex-col selection:bg-blue-200 dark:selection:bg-green-900">
      
      {/* CABEÇALHO NAS PONTAS */}
      <nav className="flex items-center justify-between px-6 md:px-10 py-5 w-full bg-white/80 dark:bg-[#0f172a]/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800/60 sticky top-0 z-10">
        <div className="cursor-pointer transition-transform hover:scale-105" onClick={(e) => navegarPara(e, 'home')} title="Voltar ao Início">
          <AIcon size="normal" />
        </div>
        
        <div className="flex items-center gap-6">
          <button onClick={alternarIdioma} className="text-xs font-semibold text-slate-500 hover:text-slate-900 dark:hover:text-white uppercase tracking-wider transition-colors">
            {idioma}
          </button>
          <div className="w-px h-4 bg-slate-300 dark:bg-slate-700"></div>
          <button onClick={alternarTema} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors" title="Alternar Tema">
            {tema === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </nav>

      {/* CONTEÚDO PRINCIPAL DINÂMICO */}
      <main className="flex-grow flex flex-col items-center pt-12 md:pt-16 px-4 w-full">
        {renderizarConteudo()}
      </main>

      {/* RODAPÉ COM LINKS ATIVOS */}
      <footer className="w-full bg-[#f8fafc] dark:bg-[#0b1120] border-t border-slate-200 dark:border-slate-800/80 pt-12 pb-8 px-6 md:px-10 mt-auto flex flex-col items-center">
        <div className="flex flex-wrap justify-center gap-12 md:gap-28 mb-12 w-full max-w-5xl">
          
          <div className="flex flex-col min-w-[140px]">
            <h4 className="font-bold text-slate-900 dark:text-white mb-4 text-sm">{t.ft_prod}</h4>
            <ul className="space-y-3 text-sm text-slate-500 dark:text-slate-400">
              <li><a href="#" onClick={(e) => navegarPara(e, 'home')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_scanner}</a></li>
              {/* O CLI no futuro apontará para a página dele */}
              <li><a href="#" className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_cli}</a></li>
            </ul>
          </div>
          
          <div className="flex flex-col min-w-[140px]">
            <h4 className="font-bold text-slate-900 dark:text-white mb-4 text-sm">{t.ft_resources}</h4>
            <ul className="space-y-3 text-sm text-slate-500 dark:text-slate-400">
              <li><a href="#" onClick={(e) => navegarPara(e, 'como_usar')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_how_to}</a></li>
              <li><a href="#" onClick={(e) => navegarPara(e, 'faq')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_faq}</a></li>
              <li><a href="#" onClick={(e) => navegarPara(e, 'scripts')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_scripts}</a></li>
            </ul>
          </div>
          
          <div className="flex flex-col min-w-[140px]">
            <h4 className="font-bold text-slate-900 dark:text-white mb-4 text-sm">{t.ft_docs}</h4>
            <ul className="space-y-3 text-sm text-slate-500 dark:text-slate-400">
              <li><a href="#" onClick={(e) => navegarPara(e, 'docs_official')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_docs_official}</a></li>
              <li><a href="#" onClick={(e) => navegarPara(e, 'termos')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_terms}</a></li>
              <li><a href="#" onClick={(e) => navegarPara(e, 'privacidade')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">{t.ft_privacy}</a></li>
            </ul>
          </div>

        </div>
        
        <div className="w-full max-w-5xl text-xs text-center text-slate-500 dark:text-slate-500 font-medium">
          <p>{t.copyright}</p>
        </div>
      </footer>
    </div>
  );
}

export default App;