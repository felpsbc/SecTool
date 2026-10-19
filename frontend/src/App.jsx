import { useState, useEffect, useRef } from 'react';
import { traducoes } from './translate';

// Ícones minimalistas
const SunIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
);
const MoonIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
);
const TerminalIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" /></svg>
);
const DownloadIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
);
const FileCheckIcon = () => (
  <svg className="w-12 h-12 text-blue-500 dark:text-green-500 mb-4" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
);

const AIcon = ({ size = "normal" }) => {
  return (
    <div className={`flex items-center justify-center rounded-xl bg-gradient-to-b from-blue-500 to-blue-700 dark:from-green-600 dark:to-green-800 text-white font-black shadow-lg ${size === "large" ? "w-16 h-16 text-4xl mr-4" : "w-10 h-10 text-2xl"}`}>
      A
    </div>
  );
};

// ==========================================
// MOTOR DE REGRAS DE SEGURANÇA (SAST ENGINE)
// ==========================================
const REGRAS_SAST = [
  { regex: /\b(eval|exec|Function)\s*\(/i, vuln: "Code Injection (RCE)", cwe: "CWE-94", owasp: "A03:2021-Injection" },
  { regex: /\b(SELECT|INSERT|UPDATE|DELETE)\b.*?\s*(WHERE|VALUES).*(?:\+|`|\$|\%s)/i, vuln: "Possível SQL Injection (Concatenação Insegura)", cwe: "CWE-89", owasp: "A03:2021-Injection" },
  { regex: /\b(password|passwd|secret|api_?key|token|auth_?token|credentials?|auth_?credentials?)\b\s*[:=]\s*['"][^'"]{8,}['"]/i, vuln: "Credencial ou Chave Exposta (Hardcoded Secret)", cwe: "CWE-798", owasp: "A07:2021-Identification and Authentication Failures" },
  { regex: /\b(innerHTML|outerHTML|document\.write)\s*=/i, vuln: "DOM XSS (Cross-Site Scripting)", cwe: "CWE-79", owasp: "A03:2021-Injection" },
  { regex: /\b(md5|sha1)\s*\(/i, vuln: "Algoritmo de Criptografia Fraco/Obsoleto", cwe: "CWE-327", owasp: "A02:2021-Cryptographic Failures" },
  { regex: /['"`]http:\/\/(?!localhost|127\.0\.0\.1)/i, vuln: "Tráfego Inseguro (Protocolo HTTP)", cwe: "CWE-319", owasp: "A02:2021-Cryptographic Failures" }
];

function App() {
  const [idioma, setIdioma] = useState('pt');
  const [tema, setTema] = useState(() => localStorage.getItem('aegis-tema') || 'dark');
  const [abaAtiva, setAbaAtiva] = useState('snippet');
  const [paginaAtual, setPaginaAtual] = useState('home');

  const [analisando, setAnalisando] = useState(false);
  const [relatorio, setRelatorio] = useState(null);
  
  const [codigoSnippet, setCodigoSnippet] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [arquivos, setArquivos] = useState([]);
  
  const [arrastando, setArrastando] = useState(false);
  const fileInputRef = useRef(null);

  const t = traducoes[idioma];

  useEffect(() => {
    const root = document.documentElement;
    if (tema === 'dark') {
      root.classList.add('dark');
      root.style.colorScheme = 'dark';
    } else {
      root.classList.remove('dark');
      root.style.colorScheme = 'light';
    }
    localStorage.setItem('aegis-tema', tema);
  }, [tema]);

  const alternarTema = () => setTema(tema === 'dark' ? 'light' : 'dark');
  const alternarIdioma = () => setIdioma(idioma === 'pt' ? 'en' : 'pt');

  const navegarPara = (e, pagina, novaAba = null) => {
    e.preventDefault();
    setPaginaAtual(pagina);
    setRelatorio(null);
    if (novaAba) setAbaAtiva(novaAba);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const mudarAba = (aba) => {
    setAbaAtiva(aba);
    setRelatorio(null);
  };

  const handleDragOver = (e) => { e.preventDefault(); setArrastando(true); };
  const handleDragLeave = (e) => { e.preventDefault(); setArrastando(false); };
  const handleDrop = (e) => {
    e.preventDefault();
    setArrastando(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setArquivos(Array.from(e.dataTransfer.files));
      setRelatorio(null);
    }
  };
  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setArquivos(Array.from(e.target.files));
      setRelatorio(null);
    }
  };
  const removerArquivo = (e) => {
    e.stopPropagation();
    setArquivos([]);
    setRelatorio(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // ---------------------------------------------------------
  // FUNÇÕES REAIS DE ANÁLISE ESTÁTICA
  // ---------------------------------------------------------
  const analisarTexto = (texto, identificador) => {
    const achados = [];
    const linhas = texto.split('\n');
    
    linhas.forEach((linhaTexto, idx) => {
      const linhaLimpa = linhaTexto.trim();

      if (linhaLimpa.startsWith('//') || linhaLimpa.startsWith('/*') || linhaLimpa.startsWith('*')) {
        return; 
      }

      REGRAS_SAST.forEach(regra => {
        if (regra.regex.test(linhaLimpa)) {
          achados.push({ vuln: regra.vuln, cwe: regra.cwe, owasp: regra.owasp, linha: `${identificador}:${idx + 1}` });
        }
      });
    });
    return achados;
  };

  const executarAnalise = () => {
    setAnalisando(true);
    setRelatorio(null);

    setTimeout(() => {
      let achadosFinais = [];

      if (abaAtiva === 'snippet' && codigoSnippet.trim()) {
        achadosFinais = analisarTexto(codigoSnippet, 'linha');
        if (achadosFinais.length === 0) achadosFinais.push({ vuln: t.clean_code, cwe: "Seguro", owasp: "N/A", linha: "Geral" });
        setRelatorio({ tipo: 'snippet', achados: achadosFinais });
        setAnalisando(false);
      } 
      
      else if (abaAtiva === 'url' && urlInput.trim()) {
        const urlStr = urlInput.toLowerCase();
        if (urlStr.startsWith("http://")) achadosFinais.push({ vuln: "Tráfego HTTP Não Criptografado", cwe: "CWE-319", owasp: "A02:2021-Cryptographic Failures", linha: "URL" });
        if (/(\?|&)(cmd|exec)=/i.test(urlStr)) achadosFinais.push({ vuln: "Possível RCE em Parâmetro de URL", cwe: "CWE-94", owasp: "A03:2021-Injection", linha: "Query String" });
        if (/(\?|&)(script|alert|img)=/i.test(urlStr)) achadosFinais.push({ vuln: "Parâmetro Suspeito de Reflected XSS", cwe: "CWE-79", owasp: "A03:2021-Injection", linha: "Query String" });
        
        if (achadosFinais.length === 0) achadosFinais.push({ vuln: t.url_safe, cwe: "Seguro", owasp: "N/A", linha: "Estrutura" });
        setRelatorio({ tipo: 'url', achados: achadosFinais });
        setAnalisando(false);
      } 
      
      else if (abaAtiva === 'file' && arquivos.length > 0) {
        const file = arquivos[0];
        const reader = new FileReader();
        reader.onload = (e) => {
          const content = e.target.result;
          achadosFinais = analisarTexto(content, file.name);
          if (achadosFinais.length === 0) achadosFinais.push({ vuln: t.file_safe, cwe: "Seguro", owasp: "N/A", linha: file.name });
          setRelatorio({ tipo: 'file', achados: achadosFinais });
          setAnalisando(false);
        };
        reader.onerror = () => {
          setRelatorio({ tipo: 'file', achados: [{ vuln: "Erro ao ler o ficheiro localmente.", cwe: "Erro", owasp: "N/A", linha: "N/A" }]});
          setAnalisando(false);
        };
        reader.readAsText(file);
      }
    }, 1200); 
  };

  const renderizarRelatorio = () => {
    if (!relatorio) return null;
    return (
      <div className="mt-6 w-full text-left p-5 bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-700/50 rounded-lg animate-fade-in shadow-inner">
        <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-200 dark:border-slate-700/50">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500">{t.report_title}</span>
          <span className="text-xs font-bold text-blue-600 dark:text-green-400 uppercase">{relatorio.tipo} SCAN</span>
        </div>
        <div className="space-y-3">
          {relatorio.achados.map((item, idx) => (
            <div key={idx} className={`p-3 bg-white dark:bg-[#151e32] border-l-4 rounded shadow-sm ${item.cwe === 'Seguro' ? 'border-blue-500 dark:border-green-500' : 'border-red-500'}`}>
              <div className="flex justify-between font-bold mb-1">
                <span className={item.cwe === 'Seguro' ? 'text-blue-600 dark:text-green-400' : 'text-red-500'}>{item.vuln}</span>
                <span className="text-slate-400 text-sm">{item.linha}</span>
              </div>
              <p className="text-xs font-mono text-slate-500 dark:text-slate-400">{item.owasp} | {item.cwe}</p>
            </div>
          ))}
        </div>
        <div className="mt-5 p-4 bg-blue-50/50 dark:bg-green-950/20 border border-blue-200/50 dark:border-green-900/30 rounded flex items-center justify-between">
          <span className="text-sm text-slate-600 dark:text-slate-300">
            {t.recommend_cli} 
            <button onClick={(e) => navegarPara(e, 'home', 'cli')} className="font-bold text-blue-600 dark:text-green-400 hover:underline">
              {t.recommend_cli_btn}
            </button>
          </span>
        </div>
      </div>
    );
  };

  const renderizarScanner = () => {
    return (
      <>
        <div className="text-center mb-10 flex flex-col items-center animate-fade-in">
          <div className="flex items-center justify-center mb-6">
            <AIcon size="large" />
            <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight text-slate-900 dark:text-white">AEGIS</h1>
          </div>
          <p className="text-sm md:text-base text-slate-500 dark:text-slate-400 max-w-xl font-medium leading-relaxed">{t.subtitle}</p>
        </div>

        <div className="w-full max-w-3xl bg-white dark:bg-[#151e32] rounded-xl shadow-sm border border-slate-200 dark:border-slate-800/60 overflow-hidden">
          <div className="relative flex items-center justify-center bg-slate-50/50 dark:bg-[#0f172a]/50 border-b border-slate-200 dark:border-slate-800/60">
            <div className="flex gap-4 md:gap-8">
              {[
                { id: 'file', label: t.tab_file },
                { id: 'url', label: t.tab_url },
                { id: 'snippet', label: t.tab_snippet }
              ].map((aba) => (
                <button
                  key={aba.id}
                  onClick={() => mudarAba(aba.id)}
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
                onClick={(e) => navegarPara(e, 'home', 'cli')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold border transition-all ${
                  abaAtiva === 'cli'
                    ? 'bg-blue-50 dark:bg-green-900/20 border-blue-200 dark:border-green-800 text-blue-700 dark:text-green-400'
                    : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                }`}
              >
                <TerminalIcon />
                <span>CLI</span>
              </button>
            </div>
          </div>

          <div className="p-8 md:p-12 min-h-[300px] flex flex-col justify-center items-center">
            {abaAtiva === 'file' && (
              <div className="w-full flex flex-col items-center">
                <div
                  className={`w-full h-auto min-h-[192px] border-2 border-dashed rounded-xl flex flex-col items-center justify-center cursor-pointer transition-all ${
                    arrastando
                      ? 'border-blue-500 bg-blue-50 dark:border-green-500 dark:bg-green-900/20'
                      : 'border-slate-300 dark:border-slate-600/60 bg-slate-50/50 hover:bg-slate-100 dark:hover:bg-slate-800/30'
                  } ${arquivos.length > 0 ? 'border-solid border-transparent dark:border-transparent bg-transparent' : ''}`}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => arquivos.length === 0 && fileInputRef.current?.click()}
                >
                  <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileChange} />
                  
                  {arquivos.length === 0 ? (
                    <>
                      <svg className="w-10 h-10 text-slate-400 mb-4 pointer-events-none" fill="currentColor" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
                      <button className="bg-white dark:bg-[#1e293b] border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 px-6 py-2 rounded font-semibold text-sm shadow-sm pointer-events-none">
                        {t.btn_choose}
                      </button>
                      <span className="text-xs text-slate-400 mt-3 pointer-events-none">{t.drag_drop}</span>
                    </>
                  ) : (
                    <div className="flex flex-col items-center w-full">
                      <FileCheckIcon />
                      <div className="flex items-center gap-2 bg-slate-200 dark:bg-[#1e293b] px-4 py-2 rounded-full mb-6 text-sm font-semibold">
                        <span className="truncate max-w-[200px]" title={arquivos[0].name}>{arquivos[0].name}</span>
                        <button onClick={removerArquivo} className="hover:text-red-500 ml-2 text-slate-500">
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                        </button>
                      </div>
                      <button 
                        onClick={executarAnalise}
                        disabled={analisando}
                        className="bg-blue-600 hover:bg-blue-700 dark:bg-green-600 dark:hover:bg-green-500 text-white px-10 py-2.5 rounded font-bold transition-colors w-full max-w-[200px]"
                      >
                        {analisando ? t.btn_scanning : t.btn_scan}
                      </button>
                    </div>
                  )}
                </div>
                {renderizarRelatorio()}
              </div>
            )}

            {abaAtiva === 'url' && (
              <div className="w-full max-w-xl flex flex-col gap-4">
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
                  </div>
                  <input 
                    type="text" 
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder={t.url_placeholder} 
                    className="w-full bg-slate-50 dark:bg-[#0b1120] text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 rounded-lg py-4 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-green-500 font-mono text-sm" 
                  />
                </div>
                <button 
                  onClick={executarAnalise}
                  disabled={analisando || !urlInput.trim()}
                  className="w-full bg-blue-600 hover:bg-blue-700 dark:bg-green-600 dark:hover:bg-green-500 text-white font-bold py-3.5 rounded-lg transition-colors disabled:opacity-50"
                >
                  {analisando ? t.btn_scanning : t.btn_search}
                </button>
                {renderizarRelatorio()}
              </div>
            )}

            {abaAtiva === 'snippet' && (
              <div className="w-full flex flex-col gap-4">
                <textarea
                  value={codigoSnippet}
                  onChange={(e) => setCodigoSnippet(e.target.value)}
                  className="w-full h-48 bg-slate-50 dark:bg-[#0b1120] text-slate-800 dark:text-green-400 border border-slate-200 dark:border-slate-700/50 rounded-lg p-4 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-green-500"
                  placeholder={t.snippet_placeholder}
                  spellCheck="false"
                />
                <button
                  onClick={executarAnalise}
                  disabled={analisando || !codigoSnippet.trim()}
                  className="self-end bg-blue-600 hover:bg-blue-700 dark:bg-green-600 dark:hover:bg-green-500 text-white px-10 py-2.5 rounded font-bold transition-colors disabled:opacity-50"
                >
                  {analisando ? t.btn_scanning : t.btn_scan}
                </button>
                {renderizarRelatorio()}
              </div>
            )}

            {abaAtiva === 'cli' && (
              <div className="w-full flex flex-col items-center text-center">
                <div className="mb-5 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-full border border-slate-200 dark:border-slate-700/50">
                  <TerminalIcon className="w-6 h-6 text-slate-600 dark:text-slate-400" />
                </div>
                <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">{t.cli_title}</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mb-8 max-w-sm">{t.cli_desc}</p>
                <div className="flex flex-col sm:flex-row gap-3 w-full max-w-md">
                  <div className="flex-grow bg-slate-100 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-300 font-mono text-sm p-3 rounded flex items-center justify-center overflow-x-auto">
                    <code>git clone https://github.com/CAMPUSCEUB/AEGIS.git</code>
                  </div>
                  <a href="https://github.com/CAMPUSCEUB/AEGIS" target="_blank" rel="noreferrer" className="flex items-center justify-center gap-2 bg-slate-800 hover:bg-slate-900 dark:bg-green-600 dark:hover:bg-green-500 text-white px-6 py-3 rounded font-bold transition-colors">
                    <DownloadIcon />
                    GitHub
                  </a>
                </div>
              </div>
            )}
          </div>
        </div>
        
        {/* BLOCO DE AVISOS: ZERO-TRUST + FALSO POSITIVO */}
        <div className="w-full max-w-2xl text-center mt-6 mb-12 px-4 flex flex-col gap-3">
          <p className="whitespace-pre-line text-xs font-bold text-slate-500 dark:text-slate-400 leading-relaxed bg-slate-100 dark:bg-[#151e32] p-3 rounded-lg shadow-sm border border-slate-200 dark:border-slate-800/80">
            🛡️ {t.disclaimer_text}
          </p>
          <p className="whitespace-pre-line text-xs font-medium text-amber-600 dark:text-amber-500 leading-relaxed bg-amber-50 dark:bg-amber-950/30 p-3 rounded-lg shadow-sm border border-amber-200 dark:border-amber-900/50">
            ⚠️ {t.false_positive_warning}
          </p>
        </div>
      </>
    );
  };

  // ---------------------------------------------------------
  // CONTEÚDO DINÂMICO DAS PÁGINAS TRADUZIDO
  // ---------------------------------------------------------
  const getConteudoPagina = () => {
    const conteudos = {
      docs_official: {
        titulo: t.ft_docs_official,
        corpo: t.docs_official_body
      },
      termos: {
        titulo: t.ft_terms,
        corpo: t.terms_body
      },
      privacidade: {
        titulo: t.ft_privacy,
        corpo: t.privacy_body
      },
      como_usar: {
        titulo: t.ft_how_to,
        corpo: t.how_to_body
      },
      faq: {
        titulo: t.ft_faq,
        corpo: t.faq_body
      },
      scripts: {
        titulo: t.ft_scripts,
        corpo: t.scripts_body
      }
    };
    return conteudos[paginaAtual];
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0f172a] text-slate-800 dark:text-slate-200 font-sans flex flex-col">
      <nav className="flex items-center justify-between px-6 md:px-10 py-5 w-full bg-white/80 dark:bg-[#0f172a]/80 backdrop-blur-md sticky top-0 z-50 border-b border-slate-200 dark:border-slate-800">
        <div className="cursor-pointer transition-transform hover:scale-105 flex items-center gap-3" onClick={(e) => navegarPara(e, 'home', 'snippet')}>
          <AIcon size="normal" />
          <span className="font-bold text-xl tracking-wide text-slate-900 dark:text-white hidden sm:block">AEGIS</span>
        </div>
        <div className="flex items-center gap-6">
          <button onClick={alternarIdioma} className="text-xs font-bold uppercase text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors">
            {idioma}
          </button>
          <div className="w-px h-4 bg-slate-300 dark:bg-slate-700"></div>
          <button onClick={alternarTema} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
            {tema === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </nav>

      <main className="flex-grow flex flex-col items-center pt-12 md:pt-16 px-4 w-full">
        {paginaAtual === 'home' ? (
          renderizarScanner()
        ) : (
          <div className="w-full max-w-4xl bg-white dark:bg-[#151e32] rounded-xl shadow-sm border border-slate-200 dark:border-slate-800 p-8 md:p-12 animate-fade-in mb-16">
            <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white mb-6 pb-6 border-b border-slate-200 dark:border-slate-800/60">
              {getConteudoPagina()?.titulo}
            </h2>
            <div className="text-slate-600 dark:text-slate-400 whitespace-pre-wrap leading-relaxed space-y-4">
              {getConteudoPagina()?.corpo.split('\n').map((linha, i) => {
                if (linha.startsWith('###')) {
                  return <h3 key={i} className="text-lg font-bold text-slate-800 dark:text-white mt-6 mb-2">{linha.replace('### ', '')}</h3>;
                }
                if (linha.startsWith('```')) return null;
                return <p key={i}>{linha}</p>;
              })}
            </div>
          </div>
        )}
      </main>

      <footer className="w-full bg-[#f8fafc] dark:bg-[#0b1120] border-t border-slate-200 dark:border-slate-800/80 pt-16 pb-8 px-6 mt-auto">
        <div className="flex flex-wrap justify-center gap-12 md:gap-28 mb-12 w-full max-w-5xl mx-auto">
          <div className="flex flex-col min-w-[140px]">
            <h4 className="font-bold text-slate-900 dark:text-white mb-4 text-sm">{t.ft_prod}</h4>
            <ul className="space-y-3 text-sm text-slate-500 dark:text-slate-400">
              <li><a href="#" onClick={(e) => navegarPara(e, 'home', 'snippet')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">AEGIS Scanner</a></li>
              <li><a href="#" onClick={(e) => navegarPara(e, 'home', 'cli')} className="hover:text-blue-600 dark:hover:text-green-400 transition-colors">AEGIS CLI</a></li>
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
        <div className="w-full max-w-5xl mx-auto text-xs text-center text-slate-500 dark:text-slate-600 font-medium border-t border-slate-200 dark:border-slate-800/50 pt-8">
          <p>{t.copyright}</p>
        </div>
      </footer>
    </div>
  );
}

export default App;