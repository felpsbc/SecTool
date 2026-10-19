export const traducoes = {
  pt: {
    subtitle: "Analise código, ficheiros e URLs para detetar vulnerabilidades de segurança.",
    tab_file: "FICHEIRO",
    tab_url: "URL",
    tab_snippet: "CÓDIGO",
    btn_choose: "Escolher ficheiro",
    btn_scan: "Analisar",
    btn_scanning: "Analisando...",
    btn_search: "Pesquisar",
    btn_github: "Ver no GitHub",
    url_placeholder: "Pesquisar ou analisar um URL (ex: https://site.com)",
    snippet_placeholder: "# Cole o seu código-fonte aqui para análise estática em tempo real...",
    disclaimer_text: "Processamento seguro (Client-Side): Os seus ficheiros e códigos nunca saem do seu navegador.\nO processamento é 100% local.",
    false_positive_warning: "Aviso: Sendo um scanner Web ultrarrápido baseado em RegEx, podem ocorrer falsos positivos.\nPara auditorias exatas com Árvore de Sintaxe Abstrata (AST), utilize a CLI.",
    cli_title: "Automatize as suas análises",
    cli_desc: "Integre o AEGIS diretamente na sua pipeline CI/CD ou terminal usando a nossa ferramenta de linha de comandos.",
    
    // Footer & Pages Titles
    ft_prod: "O nosso produto",
    ft_resources: "Recursos",
    ft_docs: "Documentação",
    ft_docs_official: "Documentação Oficial",
    ft_terms: "Termos de Uso",
    ft_privacy: "Privacidade",
    ft_how_to: "Como usar",
    ft_faq: "Perguntas Frequentes",
    ft_scripts: "Scripts de API",
    copyright: "© 2026 Aegis. Focado na análise de vulnerabilidades web e OWASP.",

    // Real Scan Results
    report_title: "Relatório de Análise Estática (SAST Web)",
    recommend_cli: "Para varreduras profundas envolvendo múltiplos ficheiros de projeto, utilize o ",
    recommend_cli_btn: "AEGIS CLI (Python)",
    file_safe: "Nenhuma assinatura maliciosa ou vulnerabilidade OWASP detetada neste ficheiro.",
    url_safe: "A estrutura do URL parece segura. Tráfego HTTPS validado.",
    drag_drop: "ou arraste e solte o ficheiro aqui",
    clean_code: "Código limpo! Nenhuma vulnerabilidade detetada no trecho fornecido.",

    // Pages Content (PT)
    docs_official_body: "### Introdução à Plataforma AEGIS\nO AEGIS é um motor de análise estática de segurança (SAST) projetado para integrar-se de forma fluida nos fluxos de desenvolvimento modernos. O nosso foco é fornecer identificação rápida e precisa de vulnerabilidades do Top 10 da OWASP.\n\n### Arquitetura do Sistema\nO ecossistema AEGIS divide-se em dois componentes principais:\n1. **Web Scanner (Client-Side SAST):** Uma interface construída em React/Vite para validação rápida. Diferente de plataformas tradicionais, o AEGIS processa os arquivos de código e snippets inteiramente dentro do seu navegador (Browser Engine), sem tráfego de dados para a nuvem.\n2. **AEGIS CLI (Motor Principal):** Uma ferramenta baseada em Python desenhada para ser orquestrada em pipelines CI/CD (GitHub Actions, GitLab CI). Ela realiza auditorias em profundidade utilizando heurística avançada e análise de grafos de fluxo de dados (DFG).",
    terms_body: "### 1. Aceitação de Termos e Responsabilidade\nAo utilizar o AEGIS Web Scanner ou a versão CLI, o utilizador reconhece que o software é fornecido \"no estado em que se encontra\" (As-Is). A equipa do AEGIS não assume qualquer responsabilidade por falsos positivos, falsos negativos ou interrupções de serviço.\n\n### 2. Uso Ético e Legalidade\nEsta ferramenta foi desenvolvida estritamente para propósitos de Defesa (Blue Team), AppSec e auditoria de código autorizado. A submissão de malware ativo, engenharia reversa para fins ilícitos ou o uso do motor contra alvos sem permissão explícita violam os nossos termos de serviço.\n\n### 3. Licenciamento de Código Aberto\nO projeto AEGIS é mantido sob uma licença de código aberto permissiva, promovendo o estudo acadêmico e melhorias pela comunidade de cibersegurança.",
    privacy_body: "### Segurança Client-Side e Zero-Trust\nNo AEGIS, adotamos a arquitetura \"Zero-Trust\". Quando interage com o nosso Scanner Web, o processamento dos seus códigos-fonte ou documentos ocorre nativamente utilizando as APIs internas do navegador (como a FileReader API).\n\n### Garantia de Não-Transmissão\n- **Código-fonte:** Não trafega na rede. É lido, analisado e descartado da memória RAM após a geração do relatório.\n- **Ficheiros:** Não realizamos nenhum tipo de upload (POST/PUT) dos arquivos enviados pelo painel web para os nossos servidores.\n\nNenhuma informação confidencial, proprietária ou de identificação pessoal (PII) é capturada, armazenada ou compartilhada pelo motor Web do AEGIS.",
    how_to_body: "### Análise Rápida via Web\n1. Escolha a aba do vetor que deseja analisar: **Ficheiro**, **URL** ou **Código**.\n2. Insira o artefato e clique em \"Analisar\". O processamento será imediato no seu lado-cliente.\n3. Verifique o relatório para identificação de CWEs (Common Weakness Enumeration).\n\n### Integração Profissional (Recomendada)\nPara uso corporativo ou auditoria de repositórios completos, utilize a CLI. Clone o repositório do GitHub e instale as dependências Python. Você poderá executar varreduras automatizadas utilizando:\n`aegis-scan --path /caminho/do/projeto --format json`",
    faq_body: "### O AEGIS é totalmente gratuito?\nSim. Tanto o Web Scanner quanto a ferramenta CLI em Python são gratuitos e open-source para a comunidade.\n\n### Quais regras o Web Scanner aplica?\nA versão web atual inspeciona falhas comuns como: Hardcoded Passwords, SQL Injections explícitos, chamadas de Remote Code Execution (RCE) como eval() e protocolos HTTP inseguros.\n\n### O Web Scanner envia o meu código para algum servidor?\nNão. As validações operam utilizando Expressões Regulares (RegEx) diretamente no JavaScript do lado do cliente (no seu navegador). O seu código nunca sai da sua máquina.",
    scripts_body: "### Acesso Programático via CLI\nA melhor forma de interagir programaticamente com o AEGIS é através do binário CLI.\n\n### Exemplo: Varredura em Pipeline CI/CD\nAdicione o seguinte passo no seu fluxo de trabalho (ex: GitLab CI ou GitHub Actions) para bloquear submissões de código vulnerável:\n\n```bash\n# Instalação do motor AEGIS\ngit clone [https://github.com/CAMPUSCEUB/AEGIS.git](https://github.com/CAMPUSCEUB/AEGIS.git)\ncd AEGIS && pip install -r requirements.txt\n\n# Execução de Análise Estrita\npython aegis.py --scan ./meu-app --severity HIGH --fail-on-warn\n```\n\n*(Nota: APIs RESTful para integração em nuvem estão no roadmap das próximas versões).*"
  },
  en: {
    subtitle: "Analyse code, files, and URLs to detect security vulnerabilities.",
    tab_file: "FILE",
    tab_url: "URL",
    tab_snippet: "SNIPPET",
    btn_choose: "Choose file",
    btn_scan: "Scan",
    btn_scanning: "Scanning...",
    btn_search: "Search",
    btn_github: "View on GitHub",
    url_placeholder: "Search or scan a URL (e.g., https://site.com)",
    snippet_placeholder: "# Paste your source code here for real-time static analysis...",
    disclaimer_text: "Secure processing (Client-Side): Your files and code never leave your browser.\nProcessing is 100% local.",
    false_positive_warning: "Warning: As an ultra-fast RegEx-based Web scanner, false positives may occur.\nFor exact audits using Abstract Syntax Trees (AST), use the CLI.",
    cli_title: "Automate your scans",
    cli_desc: "Integrate AEGIS directly into your CI/CD pipeline or terminal using our command-line tool.",
    
    // Footer & Pages Titles
    ft_prod: "Our product",
    ft_resources: "Resources",
    ft_docs: "Documentation",
    ft_docs_official: "Official Documentation",
    ft_terms: "Terms of Use",
    ft_privacy: "Privacy",
    ft_how_to: "How to use",
    ft_faq: "FAQ",
    ft_scripts: "API Scripts",
    copyright: "© 2026 Aegis. Focused on web vulnerabilities analysis and OWASP.",

    // Real Scan Results
    report_title: "Static Analysis Report (Web SAST)",
    recommend_cli: "For deep scans involving multiple project files, use the ",
    recommend_cli_btn: "AEGIS CLI (Python)",
    file_safe: "No malicious signatures or OWASP vulnerabilities detected in this file.",
    url_safe: "URL structure appears secure. HTTPS traffic validated.",
    drag_drop: "or drag and drop file here",
    clean_code: "Clean code! No vulnerabilities detected in the provided snippet.",

    // Pages Content (EN)
    docs_official_body: "### Introduction to the AEGIS Platform\nAEGIS is a Static Application Security Testing (SAST) engine designed to integrate seamlessly into modern development workflows. Our focus is to provide fast and accurate identification of OWASP Top 10 vulnerabilities.\n\n### System Architecture\nThe AEGIS ecosystem is divided into two main components:\n1. **Web Scanner (Client-Side SAST):** A React/Vite-built interface for quick validation. Unlike traditional platforms, AEGIS processes code files and snippets entirely within your browser engine, with no data traffic to the cloud.\n2. **AEGIS CLI (Core Engine):** A Python-based tool designed to be orchestrated in CI/CD pipelines (GitHub Actions, GitLab CI). It performs in-depth audits using advanced heuristics and Data Flow Graph (DFG) analysis.",
    terms_body: "### 1. Acceptance of Terms and Liability\nBy using the AEGIS Web Scanner or CLI version, the user acknowledges that the software is provided \"As-Is\". The AEGIS team assumes no responsibility for false positives, false negatives, or service interruptions.\n\n### 2. Ethical Use and Legality\nThis tool was strictly developed for Defense (Blue Team), AppSec, and authorized code auditing purposes. Submitting active malware, reverse engineering for illicit purposes, or using the engine against targets without explicit permission violates our terms of service.\n\n### 3. Open Source Licensing\nThe AEGIS project is maintained under a permissive open-source license, promoting academic study and improvements by the cybersecurity community.",
    privacy_body: "### Client-Side Security and Zero-Trust\nAt AEGIS, we adopt a \"Zero-Trust\" architecture. When you interact with our Web Scanner, the processing of your source codes or documents occurs natively using internal browser APIs (such as the FileReader API).\n\n### Non-Transmission Guarantee\n- **Source Code:** Does not travel over the network. It is read, analyzed, and discarded from RAM after the report is generated.\n- **Files:** We do not perform any kind of upload (POST/PUT) of the files submitted through the web panel to our servers.\n\nNo confidential, proprietary, or Personally Identifiable Information (PII) is captured, stored, or shared by the AEGIS Web engine.",
    how_to_body: "### Quick Web Analysis\n1. Choose the tab for the vector you want to analyze: **File**, **URL**, or **Snippet**.\n2. Insert the artifact and click \"Scan\". Processing will be immediate on your client-side.\n3. Check the report for CWE (Common Weakness Enumeration) identification.\n\n### Professional Integration (Recommended)\nFor corporate use or full repository auditing, use the CLI. Clone the GitHub repository and install the Python dependencies. You can run automated scans using:\n`aegis-scan --path /path/to/project --format json`",
    faq_body: "### Is AEGIS completely free?\nYes. Both the Web Scanner and the Python CLI tool are free and open-source for the community.\n\n### What rules does the Web Scanner apply?\nThe current web version inspects common flaws such as: Hardcoded Passwords, explicit SQL Injections, Remote Code Execution (RCE) calls like eval(), and insecure HTTP protocols.\n\n### Does the Web Scanner send my code to any server?\nNo. Validations operate using Regular Expressions (RegEx) directly in client-side JavaScript (in your browser). Your code never leaves your machine.",
    scripts_body: "### Programmatic Access via CLI\nThe best way to interact programmatically with AEGIS is through the CLI binary.\n\n### Example: CI/CD Pipeline Scan\nAdd the following step in your workflow (e.g., GitLab CI or GitHub Actions) to block vulnerable code submissions:\n\n```bash\n# Install AEGIS engine\ngit clone [https://github.com/CAMPUSCEUB/AEGIS.git](https://github.com/CAMPUSCEUB/AEGIS.git)\ncd AEGIS && pip install -r requirements.txt\n\n# Run Strict Analysis\npython aegis.py --scan ./my-app --severity HIGH --fail-on-warn\n```\n\n*(Note: RESTful APIs for cloud integration are on the roadmap for upcoming releases).*"
  }
};