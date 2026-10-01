// Painel do resultado de POST /analisar, no mesmo estilo do painel de analise.
// Candidatos heuristicos (confianca baixa, ex. IDOR) ficam separados: o motor
// nao afirma que sao vulnerabilidades, so pede revisao manual.

const CORES_SEVERIDADE = {
  alta: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800',
  media: 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800',
  baixa: 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
};

const Achado = ({ achado, t }) => (
  <div className="border border-slate-200 dark:border-slate-800 rounded-lg p-5 bg-slate-50/50 dark:bg-[#0f172a]/30">
    <div className="flex flex-wrap items-center gap-2 mb-2">
      <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${CORES_SEVERIDADE[achado.severidade] || CORES_SEVERIDADE.baixa}`}>
        {t.sev[achado.severidade] || achado.severidade}
      </span>
      <span className="text-sm font-bold text-slate-900 dark:text-white">{achado.cwe} {achado.vulnerabilidade}</span>
      <span className="text-xs text-slate-500 dark:text-slate-400">{achado.owasp}</span>
    </div>
    <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
      {achado.arquivo}:{achado.linha} · {t.res_confidence} {t.sev[achado.confianca] || achado.confianca}
    </p>
    <pre className="bg-slate-100 dark:bg-[#0b1120] text-slate-800 dark:text-green-400 border border-slate-300 dark:border-slate-700 rounded-lg p-3 font-mono text-xs overflow-x-auto mb-3 whitespace-pre-wrap break-all">{achado.trecho}</pre>
    <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">{achado.descricao}</p>
    <p className="text-sm text-slate-600 dark:text-slate-400">
      <span className="font-semibold text-slate-800 dark:text-slate-200">{t.res_fix} </span>{achado.recomendacao}
    </p>
  </div>
);

function Resultado({ resultado, t }) {
  const { resumo, varredura, achados } = resultado;
  const rastreados = achados.filter((a) => a.confianca !== 'baixa');
  const candidatos = achados.filter((a) => a.confianca === 'baixa');

  return (
    <div className="w-full max-w-3xl bg-white dark:bg-[#151e32] rounded-xl shadow-sm border border-slate-200 dark:border-slate-800/80 p-8 md:p-10 mt-6 text-left animate-fade-in">
      <h2 className="text-xl font-extrabold text-slate-900 dark:text-white mb-2">{t.res_title}</h2>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-6">
        {t.res_files}: {varredura.arquivos_analisados} · {t.res_config}: {varredura.arquivos_de_configuracao}
        {varredura.arquivos_com_falha > 0 && ` · ${t.res_failed}: ${varredura.arquivos_com_falha}`}
      </p>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        {[
          [t.res_total, resumo.total],
          [t.sev.alta, resumo.por_severidade.alta || 0],
          [t.sev.media, resumo.por_severidade.media || 0],
          [t.res_candidates, resumo.candidatos_heuristicos],
        ].map(([rotulo, valor]) => (
          <div key={rotulo} className="border border-slate-200 dark:border-slate-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-extrabold text-blue-600 dark:text-green-500">{valor}</div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mt-1">{rotulo}</div>
          </div>
        ))}
      </div>

      {achados.length === 0 && (
        <p className="text-sm text-slate-600 dark:text-slate-400">{t.res_none}</p>
      )}

      {rastreados.length > 0 && (
        <div className="flex flex-col gap-4 mb-8">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">{t.res_tracked}</h3>
          {rastreados.map((achado, i) => <Achado key={`r${i}`} achado={achado} t={t} />)}
        </div>
      )}

      {candidatos.length > 0 && (
        <div className="flex flex-col gap-4">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">{t.res_candidates}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t.res_candidates_note}</p>
          {candidatos.map((achado, i) => <Achado key={`c${i}`} achado={achado} t={t} />)}
        </div>
      )}

      {varredura.falhas.length > 0 && (
        <div className="mt-8 text-xs text-slate-500 dark:text-slate-400">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-2">{t.res_failed}</h3>
          {varredura.falhas.map((f, i) => (
            <p key={i}>{f.arquivo}{f.linha ? `:${f.linha}` : ''} — {f.mensagem}</p>
          ))}
        </div>
      )}
    </div>
  );
}

export default Resultado;
