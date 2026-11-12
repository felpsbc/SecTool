# Histórico de mudanças

Registre aqui as mudanças relevantes por sprint ou marco avaliativo.

## Uso simplificado e organização do repositório

- `aegis.py` na raiz: modo guiado (dois cliques / arrastar a pasta) e comandos (`--testar`, `--saida`, `--api`), preparando o ambiente sozinho.
- `AEGIS.ipynb`: notebook Google Colab que abre direto numa caixa para colar código; projeto inteiro (GitHub, zip, Drive) e métricas como etapas opcionais.
- README reescrito: início rápido, guias Windows e Linux, leitura do relatório, problemas comuns e mapa de "onde está cada coisa".
- `docs/teste/`: exemplos renomeados por conteúdo, guia (`README.md`) e roteiro de demonstração (`ROTEIRO_DE_DEMONSTRACAO.md`).
- Limpeza: removidos arquivos sem uso (`package-lock.json` vazio na raiz, imagens do template do Vite, `App.css` vazio); `TOOL/CLAUDE.md` → `TOOL/PRINCIPIOS.md`; `docs/API.md` → `docs/api.md`; auditoria da documentação movida para `docs/historico/`.
- Documentação atualizada com números conferidos: 613 testes passando; precisão 1.00, recall 0.97, F1 0.98.

## Licença e uso

- Projeto passa a ser distribuído sob a licença MIT (`LICENSE`), substituindo o placeholder institucional.
- README ganha a seção "Uso responsável" (análise só de código próprio ou autorizado; sem garantia; responsabilidade de quem usa).

## Motor owaspscan (TOOL/)

- Protótipo inicial (Fases 0-9): contrato de achado, camada AST, motor de taint intraprocedural, detectores de SQLi/XSS/IDOR, relatório texto/JSON, CLI (`python -m owaspscan`) e avaliação contra corpus rotulado.
- Fases 10-16 (versão 0.2.0): mapa CWE→OWASP estendido (16 CWEs), consultas estruturais, XXE, path traversal, open redirect, CSRF, rota sem autorização, falhas de autenticação (JWT, hash, senha, cookies, sessão, rate limit) e credenciais fixas em código e arquivos de configuração.
- Fases 17-19: API HTTP (FastAPI, extra opcional `[api]`) — `POST /analisar` aceitando formulário e JSON, `GET /saude`, OpenAPI em `/docs`.

## Frontend

- Protótipo base da interface web (React 19 / Vite 8 / Tailwind): tema claro/escuro, i18n pt/en, abas de análise.

## Documentação

- Documentação técnica em `docs/`: arquitetura, estrutura, instalação, configuração, API, banco de dados, fluxos, segurança, guia do desenvolvedor e auditoria da documentação.
- README raiz reescrito como porta de entrada do projeto.

## Sprint 00 - Planejamento

- Criação do repositório.
- Definição do problema, da equipe, dos papéis e do backlog inicial.

## Integração site + API

> Situação atual: o site publicado voltou a fazer a análise no navegador e não chama a API; `src/api.js` e `src/Resultado.jsx` seguem prontos para religar (ver `docs/deploy.md`, Apêndice D).

- Site (`frontend/`) ligado à API do OWASP-Scan: abas Ficheiro, Código e URL
  chamam `POST /analisar` e exibem o resultado na página (achados rastreados
  separados dos candidatos heurísticos).
- Proxy `/api` no Vite para desenvolvimento; `VITE_API_URL` para produção.
- Página "Scripts de API" passa a mostrar o endpoint real.
- Roteiro de teste com app vulnerável e resultado esperado em `docs/teste/`,
  conferido automaticamente por `TOOL/tests/test_documento_teste.py`.
