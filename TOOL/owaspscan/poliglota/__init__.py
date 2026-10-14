"""Analise de linguagens alem de Python (JavaScript/TypeScript, Java, PHP, HTML).

A stdlib so tem parser de Python, entao estas linguagens dependem do
tree-sitter, instalado como extra opcional (`pip install -e ".[linguagens]"`).
Sem ele, o nucleo continua funcionando: os arquivos dessas linguagens sao
registrados como falha de leitura com motivo "dependencia", nunca ignorados
em silencio.

O principio arquitetural e o mesmo do nucleo Python: deteccao sobre a AST
(a arvore concreta do tree-sitter), nunca regex, com taint tracking de fonte
ate sink. Cada linguagem entra como um `Perfil` (ver `perfil.py`).
"""
