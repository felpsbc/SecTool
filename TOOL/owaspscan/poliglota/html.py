"""HTML: JavaScript embutido e formularios sem token CSRF.

HTML nao tem fluxo de dados proprio. O que importa nele e:

- `<script>` inline e atributos de evento (`onclick="..."`): o JavaScript
  e extraido da arvore do HTML e analisado pelo perfil JavaScript, com a
  linha deslocada para a posicao real na pagina;
- `<form method="post">` sem campo de token CSRF: CANDIDATO (confianca
  baixa), porque o token pode ser injetado por template ou middleware que
  a analise estatica nao ve.
"""

from __future__ import annotations

from owaspscan.achado import Achado, criar_achado
from owaspscan.poliglota.detector import DetectorPoliglota
from owaspscan.poliglota.fonte import ArquivoPoliglota, analisar_texto_poliglota
from owaspscan.poliglota.javascript import PERFIL_JAVASCRIPT

# <script type="..."> que nao e JavaScript (templates, JSON, dados).
_TIPOS_DE_SCRIPT_JS = frozenset(
    {"", "text/javascript", "application/javascript", "module", "text/babel", "text/jsx"}
)

# Partes de nome de campo que indicam token anti-CSRF.
_MARCAS_DE_TOKEN = ("csrf", "xsrf", "token", "authenticity", "requestverification", "nonce")

RECOMENDACAO_CSRF = (
    "Inclua um token anti-CSRF por sessao em todo formulario que altera "
    "estado (<input type=\"hidden\" name=\"csrf_token\" ...>) e valide-o no "
    "servidor; frameworks fazem isso com {% csrf_token %} (Django), @csrf "
    "(Laravel) ou th:action (Spring/Thymeleaf). Cookie de sessao com "
    "SameSite=Lax reduz, mas nao substitui, o token."
)


def _texto(no) -> str:
    return no.text.decode("utf-8", "replace")


def _tag(no) -> str:
    """Nome da tag de um element/script_element, em minusculas."""
    inicio = next((f for f in no.named_children if f.type in ("start_tag", "self_closing_tag")), None)
    if inicio is None:
        return ""
    nome = next((f for f in inicio.named_children if f.type == "tag_name"), None)
    return _texto(nome).lower() if nome is not None else ""


def _atributos(no) -> dict[str, object]:
    """nome do atributo (minusculo) -> no do valor (ou None se sem valor)."""
    inicio = next((f for f in no.named_children if f.type in ("start_tag", "self_closing_tag")), None)
    atributos: dict[str, object] = {}
    if inicio is None:
        return atributos
    for atributo in inicio.named_children:
        if atributo.type != "attribute":
            continue
        nome = next((f for f in atributo.named_children if f.type == "attribute_name"), None)
        valor = next(
            (f for f in atributo.named_children if f.type in ("attribute_value", "quoted_attribute_value")),
            None,
        )
        if valor is not None and valor.type == "quoted_attribute_value":
            valor = next((f for f in valor.named_children if f.type == "attribute_value"), None)
        if nome is not None:
            atributos[_texto(nome).lower()] = valor
    return atributos


def _valor(atributos: dict, nome: str) -> str:
    no = atributos.get(nome)
    return _texto(no).strip() if no is not None else ""


def _percorrer(no):
    pilha = [no]
    while pilha:
        atual = pilha.pop()
        yield atual
        pilha.extend(reversed(atual.named_children))


def _javascript_embutido(arquivo: ArquivoPoliglota):
    """(codigo, linha inicial) de cada <script> inline e atributo on*."""
    for no in _percorrer(arquivo.raiz):
        if no.type == "script_element":
            atributos = _atributos(no)
            if "src" in atributos or _valor(atributos, "type").lower() not in _TIPOS_DE_SCRIPT_JS:
                continue
            corpo = next((f for f in no.named_children if f.type == "raw_text"), None)
            if corpo is not None:
                yield corpo.text, arquivo.linha_de(corpo)
        elif no.type == "element":
            for nome, valor in _atributos(no).items():
                if nome.startswith("on") and valor is not None:
                    yield valor.text, arquivo.linha_de(valor)


def _form_protegido(form) -> bool:
    for no in _percorrer(form):
        if no.type == "element" and _tag(no) == "input":
            nome = _valor(_atributos(no), "name").lower()
            if any(marca in nome for marca in _MARCAS_DE_TOKEN):
                return True
        # Token emitido por template: {% csrf_token %}, @csrf, csrf_field()...
        if no.type == "text" and any(marca in _texto(no).lower() for marca in ("csrf", "xsrf")):
            return True
    return False


def _formularios_sem_csrf(arquivo: ArquivoPoliglota) -> list[Achado]:
    achados: list[Achado] = []
    for no in _percorrer(arquivo.raiz):
        if no.type != "element" or _tag(no) != "form":
            continue
        if _valor(_atributos(no), "method").lower() != "post" or _form_protegido(no):
            continue
        inicio = no.named_children[0]
        achados.append(
            criar_achado(
                arquivo=arquivo.arquivo,
                linha=arquivo.linha_de(no),
                cwe="CWE-352",
                severidade="media",
                confianca="baixa",
                trecho=arquivo.trecho_de(inicio),
                descricao=(
                    "Candidato a CSRF (requer revisao manual): formulario POST sem "
                    "campo de token anti-CSRF. O token pode ser inserido por "
                    "JavaScript, template ou middleware fora do escopo analisado, "
                    "por isso este achado NAO afirma vulnerabilidade."
                ),
                recomendacao=RECOMENDACAO_CSRF,
            )
        )
    return achados


def detectar_html(arquivo: ArquivoPoliglota) -> list[Achado]:
    achados = _formularios_sem_csrf(arquivo)
    detector = DetectorPoliglota(PERFIL_JAVASCRIPT)
    for codigo, linha in _javascript_embutido(arquivo):
        embutido = analisar_texto_poliglota(
            codigo, "javascript", arquivo.arquivo, linha_inicial=linha
        )
        achados += detector.detectar(embutido)
    return achados
