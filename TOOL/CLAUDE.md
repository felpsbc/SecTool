# Projeto: OWASP-Scan — Analisador de Vulnerabilidades em Código Python

## Contexto
Ferramenta de Iniciação Científica (Ciência da Computação, UniCEUB).
Analisa código Python (Django/Flask) e detecta vulnerabilidades do
OWASP Top 10, começando por SQLi, XSS e IDOR. Emite um resumo
executivo dos achados.

## Princípio arquitetural (NÃO VIOLAR)
- Detecção baseada em AST (módulo `ast` da stdlib), NUNCA regex frágil.
- O motor é taint tracking: rastreia dados de FONTES não confiáveis
  até SINKS perigosos, verificando se há SANITIZAÇÃO no caminho.
- Cada achado é normalizado para uma CWE e mapeado ao OWASP Top 10.
- IDOR é heurístico: reporta CANDIDATOS para revisão manual, com
  baixa confiança declarada. Não afirmar certeza sobre IDOR.
- Honestidade científica acima de cobertura: preferir reportar
  confiança calibrada a inflar detecções.

## Stack
- Python 3.11+, apenas stdlib no núcleo (ast, dataclasses, json, pathlib).
- Testes com pytest. Sem frameworks web, sem dependências pesadas.

## Formato do achado (contrato interno, fixo)
Todo detector devolve objetos com estes campos:
  arquivo, linha, cwe (ex. "CWE-89"), owasp (ex. "A03:2021 Injection"),
  vulnerabilidade (ex. "SQL Injection"), severidade, confianca
  (alta/media/baixa), trecho, descricao, recomendacao.

## Mapeamento CWE -> OWASP (usar exatamente este, não inventar)
  CWE-89  -> A03:2021 Injection            (SQL Injection)
  CWE-79  -> A03:2021 Injection            (Cross-Site Scripting)
  CWE-639 -> A01:2021 Broken Access Control (IDOR)
  CWE-22   -> A01:2021 Broken Access Control (Path Traversal)
  CWE-601  -> A01:2021 Broken Access Control (Open Redirect)
  CWE-352  -> A01:2021 Broken Access Control (Cross-Site Request Forgery)
  CWE-862  -> A01:2021 Broken Access Control (Missing Authorization)
  CWE-916  -> A02:2021 Cryptographic Failures (Weak Password Hash)
  CWE-256  -> A04:2021 Insecure Design (Unprotected Storage of Credentials)
  CWE-611  -> A05:2021 Security Misconfiguration (XML External Entity (XXE))
  CWE-614  -> A05:2021 Security Misconfiguration (Cookie Without Secure Flag)
  CWE-1004 -> A05:2021 Security Misconfiguration (Cookie Without HttpOnly Flag)
  CWE-287  -> A07:2021 Identification and Authentication Failures (Improper Authentication)
  CWE-307  -> A07:2021 Identification and Authentication Failures (Excessive Authentication Attempts)
  CWE-613  -> A07:2021 Identification and Authentication Failures (Insufficient Session Expiration)
  CWE-798  -> A07:2021 Identification and Authentication Failures (Hard-coded Credentials)
  Fonte: "List of Mapped CWEs" oficial do OWASP Top 10:2021. Hash fraco de
  senha (A02), senha em texto puro (A04), cookies e XXE (A05) seguem a
  categoria oficial da CWE, nao o tema do detector que os encontra.

## Regras de trabalho
- Trabalhe em fases pequenas. Ao fim de cada fase, escreva o teste,
  RODE com pytest e me mostre a saída antes de seguir.
- Cada fase que passa nos testes termina com um git commit.
- Explique decisões de design em 1-2 linhas antes de codar.
- Se algo exigir suposição sobre escopo, PERGUNTE em vez de assumir.