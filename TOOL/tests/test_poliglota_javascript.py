"""Fase 22: motor poliglota (tree-sitter) e perfil JavaScript/TypeScript."""

import pytest

pytest.importorskip("tree_sitter_javascript")

from conftest import DIRETORIO_AMOSTRAS
from owaspscan.metricas import avaliar, carregar_gabarito
from owaspscan.poliglota import fonte
from owaspscan.poliglota.fonte import (
    analisar_arquivo_poliglota,
    analisar_texto_poliglota,
    linguagem_de,
)
from owaspscan.poliglota.registro import detectar_poliglota
from owaspscan.varredura import executar

POLIGLOTA = DIRETORIO_AMOSTRAS / "poliglota"


def achados(codigo: str, linguagem: str = "javascript"):
    arquivo = analisar_texto_poliglota(codigo, linguagem, "teste.js")
    return sorted(detectar_poliglota(arquivo), key=lambda a: (a.linha, a.cwe))


def pares(codigo: str, linguagem: str = "javascript"):
    return [(a.linha, a.cwe) for a in achados(codigo, linguagem)]


class TestDescoberta:
    @pytest.mark.parametrize(
        "nome,esperado",
        [
            ("app.js", "javascript"),
            ("app.mjs", "javascript"),
            ("Tela.jsx", "javascript"),
            ("servico.ts", "typescript"),
            ("Tela.tsx", "tsx"),
            ("vendor.min.js", None),
            ("tipos.d.ts", None),
            ("app.py", None),
        ],
    )
    def test_linguagem_pela_extensao(self, nome, esperado):
        assert linguagem_de(nome) == esperado

    def test_node_modules_e_ignorado(self, tmp_path):
        (tmp_path / "node_modules" / "lib").mkdir(parents=True)
        (tmp_path / "node_modules" / "lib" / "x.js").write_text("eval(1)")
        (tmp_path / "app.js").write_text("const a = 1;")
        assert [p.name for p in fonte.descobrir_arquivos_poliglotas(tmp_path)] == ["app.js"]

    def test_sem_tree_sitter_vira_falha_de_dependencia(self, tmp_path, monkeypatch):
        def ausente(linguagem):
            raise fonte.DependenciaAusente(fonte.MENSAGEM_SEM_TREE_SITTER)

        monkeypatch.setattr(fonte, "parser_para", ausente)
        caminho = tmp_path / "app.js"
        caminho.write_text("const a = 1;")
        falha = analisar_arquivo_poliglota(caminho, tmp_path)
        assert falha.motivo == "dependencia"
        assert "[linguagens]" in falha.mensagem

    def test_varredura_mista_conta_por_linguagem(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.js").write_text("const x = 1;\n")
        (tmp_path / "c.ts").write_text("const x: number = 1;\n")
        varredura = executar(tmp_path)
        assert varredura.arquivos_analisados == 3
        assert varredura.arquivos_por_linguagem == {
            "python": 1,
            "javascript": 1,
            "typescript": 1,
        }


class TestTaint:
    def test_concatenacao_direta_e_alta(self):
        (achado,) = achados(
            'app.get("/", (req, res) => { db.query("SELECT " + req.query.id); });'
        )
        assert (achado.cwe, achado.confianca) == ("CWE-89", "alta")
        assert "req.query" in achado.descricao

    def test_parametro_separado_nao_e_sqli(self):
        assert pares('db.query("SELECT ?", [req.query.id]);') == []

    def test_desestruturacao_propaga(self):
        codigo = "const { a, b: c } = req.body;\ndb.query(c);"
        assert pares(codigo) == [(2, "CWE-89")]

    def test_closure_herda_taint(self):
        codigo = "const id = req.query.id;\nfunction f() {\n  db.query(id);\n}"
        assert pares(codigo) == [(3, "CWE-89")]

    def test_atribuicao_em_cadeia(self):
        codigo = "let a = req.query.x;\nlet b = a;\nlet c = `${b}`;\ndb.query(c);"
        assert pares(codigo) == [(4, "CWE-89")]

    def test_propriedade_homonima_nao_contamina(self):
        # `id` contaminado nao torna `usuario.id` contaminado
        codigo = "const id = req.query.id;\ndb.query('x' + usuario.id);"
        assert pares(codigo) == []

    def test_chamada_desconhecida_rebaixa_para_media(self):
        (achado,) = achados("db.query(montar(req.query.q));")
        assert achado.confianca == "media"
        assert "funcao nao analisada" in achado.descricao

    def test_atribuicao_condicional_rebaixa_para_media(self):
        codigo = "let q = 'x';\nif (ok) { q = req.query.q; }\ndb.query(q);"
        (achado,) = achados(codigo)
        assert achado.confianca == "media"

    def test_mutador_push_contamina_o_array(self):
        codigo = "const p = [];\np.push(req.query.x);\nres.send(p.join(''));"
        assert pares(codigo) == [(3, "CWE-79")]


class TestSanitizacao:
    def test_conversao_numerica_neutraliza_tudo(self):
        codigo = "const n = parseInt(req.query.n);\ndb.query('x' + n);\nres.send(n);"
        assert pares(codigo) == []

    def test_escape_html_nao_neutraliza_sql(self):
        codigo = "const t = escapeHtml(req.query.t);\nres.send(t);\ndb.query(t);"
        assert pares(codigo) == [(3, "CWE-89")]

    def test_basename_neutraliza_so_caminho(self):
        codigo = "const n = path.basename(req.query.n);\nfs.readFileSync(n);\nres.send(n);"
        assert pares(codigo) == [(3, "CWE-79")]

    def test_dompurify_neutraliza_innerhtml(self):
        assert pares("el.innerHTML = DOMPurify.sanitize(location.hash);") == []

    def test_textcontent_nao_e_sink(self):
        assert pares("el.textContent = location.hash;") == []


class TestGuardas:
    def test_redirect_com_if_sobre_o_dado_cai_para_media(self):
        codigo = (
            "const d = req.query.d;\n"
            "if (d.startsWith('/')) { res.redirect(d); }"
        )
        (achado,) = achados(codigo)
        assert (achado.cwe, achado.confianca) == ("CWE-601", "media")
        assert "verificacao condicional" in achado.descricao


class TestCredenciais:
    def test_segredo_literal_e_mascarado(self):
        (achado,) = achados('const API_KEY = "sk_live_123456";')
        assert achado.cwe == "CWE-798"
        assert "sk_live_123456" not in achado.trecho

    def test_chave_de_objeto_e_atributo_jsx(self):
        codigo = 'const c = { password: "hunter22" };\nconst e = <Mapa apiKey="AIzaQualquer" />;'
        assert pares(codigo, "tsx") == [(1, "CWE-798"), (2, "CWE-798")]

    def test_variavel_de_ambiente_e_placeholder_nao_sao_achado(self):
        codigo = 'const SECRET = process.env.SECRET;\nconst TOKEN = "<seu-token>";'
        assert pares(codigo) == []


class TestCorpus:
    def test_gabarito_le_comentario_de_barra_dupla(self):
        itens = carregar_gabarito(POLIGLOTA / "vulneravel" / "dom.js")
        assert {i.cwe for i in itens} == {"CWE-79", "CWE-601", "CWE-798"}

    def test_corpus_vulneravel_sem_falso_positivo_nem_negativo_inesperado(self):
        metricas = avaliar(POLIGLOTA / "vulneravel")["geral"]
        assert metricas.fp == 0
        assert metricas.fn == metricas.fn_conhecidos  # so limitacoes declaradas

    def test_corpus_seguro_nao_tem_achado(self):
        assert executar(POLIGLOTA / "seguro").achados == ()
