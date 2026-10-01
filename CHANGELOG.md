# Histórico de mudanças

Registre aqui as mudanças relevantes por sprint ou marco avaliativo.

## Motor owaspscan (TOOL/)

- Protótipo inicial (Fases 0-9): contrato de achado, camada AST, motor de taint intraprocedural, detectores de SQLi/XSS/IDOR, relatório texto/JSON, CLI (`python -m owaspscan`) e avaliação contra corpus rotulado.
- Fases 10-16 (versão 0.2.0): mapa CWE→OWASP estendido (16 CWEs), consultas estruturais, XXE, path traversal, open redirect, CSRF, rota sem autorização, falhas de autenticação (JWT, hash, senha, cookies, sessão, rate limit) e credenciais fixas em código e arquivos de configuração.
- Fases 17-19: API HTTP (FastAPI, extra opcional `[api]`) — `POST /analisar` aceitando formulário e JSON, `GET /saude`, OpenAPI em `/docs`.

## Frontend

- Protótipo base da interface web (React 19 / Vite 8 / Tailwind): tema claro/escuro, i18n pt/en, abas de análise. Ainda sem integração com a API.

## Documentação

- Documentação técnica em `docs/`: arquitetura, estrutura, instalação, configuração, API, banco de dados, fluxos, segurança, guia do desenvolvedor e auditoria da documentação.
- README raiz reescrito como porta de entrada do projeto.

## Sprint 00 - Planejamento

- Criação do repositório.
- Definição do problema, da equipe, dos papéis e do backlog inicial.

## Integração site + API

- Site (`frontend/`) ligado à API do OWASP-Scan: abas Ficheiro, Código e URL
  chamam `POST /analisar` e exibem o resultado na página (achados rastreados
  separados dos candidatos heurísticos).
- Proxy `/api` no Vite para desenvolvimento; `VITE_API_URL` para produção.
- Página "Scripts de API" passa a mostrar o endpoint real.
- Roteiro de teste com app vulnerável e resultado esperado em `docs/teste/`,
  conferido automaticamente por `TOOL/tests/test_documento_teste.py`.
