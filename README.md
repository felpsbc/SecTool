# AEGIS CODEtucional 

## Identificação do repositório 

| Campo | Informação |
| --- | --- |
| Instituição | CEUB |
| Organização no GitHub | CampusCEUB |
| Professor(a) responsável pela criação: | Professor Lucas Rodrigues - 128050 |
| Equipe | Felipe Barcelos de Carvalho, Lucas de Salles Almeida Moura, João Marcelo Guimarães Dourado, Marcos Vinícius Rocha |
| IDProjeto | 20260229 |

## Problema

Assistentes de programação baseados em LLMs aceleram o desenvolvimento, mas não garantem segurança: estudos indicam que entre 40% e 45% do código gerado por IA contém vulnerabilidades conhecidas (Pearce, 2022; Veracode, 2025). O risco se agrava porque esse código costuma ir para produção sem revisão, seja por pressão de prazos, falta de conhecimento especializado em segurança ou excesso de confiança no que a IA produz (Perry, 2023).

## Solução proposta

O **AEGIS-CODE** é uma ferramenta de análise estática de segurança (SAST) que atua como barreira automática entre o código gerado por IA e o ambiente de produção.

- **Detecção focada em LLMs:** regras mapeadas ao CWE e OWASP Top 10 para as falhas mais comuns em código gerado por IA, além da verificação de pacotes inexistentes (*package hallucination*).
- **Integração no fluxo:** CLI, hook de pre-commit e pipeline de CI/CD que bloqueia merges com achados críticos.
- **Priorização por severidade:** classificação inspirada no CVSS v3.1 para reduzir o excesso de alertas.
- **Remediação educativa:** cada achado vem com explicação acessível e exemplo de correção.

## Estrutura deste repositório

| Item | Link |
| --- | --- |
| Backlog | Vincular o GitHub Project |
| Sprints | [sprints/README.md](sprints/README.md) |
| Entregas | [entregas/README.md](entregas/README.md) |
| Requisitos | [docs/requisitos.md](docs/requisitos.md) |
| Arquitetura | [docs/arquitetura.md](docs/arquitetura.md) |
