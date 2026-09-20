"""Fase 6: detector heuristico de IDOR (CWE-639).

Este detector reporta CANDIDATOS. Os testes verificam tanto o padrao
detectado quanto a honestidade da forma como ele e reportado.
"""

import pytest

from conftest import DIRETORIO_AMOSTRAS, linhas_esperadas
from owaspscan.analisador import analisar_arquivo, analisar_texto
from owaspscan.detectores.idor import PREFIXO_CANDIDATO, DetectorIdor
from owaspscan.motor.taint import analisar_taint

AMOSTRA_VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_idor.py"
AMOSTRA_SEGURA = DIRETORIO_AMOSTRAS / "seguro" / "flask_idor.py"

ROTA = '@app.route("/r/<item_id>")\ndef view(item_id):\n{corpo}\n'


def detectar(fonte: str, arquivo: str = "app.py"):
    analisado = analisar_texto(fonte, arquivo)
    return DetectorIdor().detectar(analisado, analisar_taint(analisado))


def detectar_em_rota(corpo: str):
    return detectar(ROTA.format(corpo=corpo))


def detectar_arquivo(caminho):
    analisado = analisar_arquivo(caminho, caminho.parent)
    return DetectorIdor().detectar(analisado, analisar_taint(analisado))


class TestAmostraVulneravel:
    def test_detecta_exatamente_as_linhas_do_gabarito(self):
        achados = detectar_arquivo(AMOSTRA_VULNERAVEL)
        assert sorted(a.linha for a in achados) == linhas_esperadas(
            AMOSTRA_VULNERAVEL, "CWE-639"
        )

    def test_classificacao_segue_o_contrato(self):
        for achado in detectar_arquivo(AMOSTRA_VULNERAVEL):
            assert achado.cwe == "CWE-639"
            assert achado.owasp == "A01:2021 Broken Access Control"
            assert achado.vulnerabilidade == "IDOR"
            assert achado.severidade == "media"


class TestHonestidadeDoRelato:
    def test_confianca_e_sempre_baixa(self):
        achados = detectar_arquivo(AMOSTRA_VULNERAVEL)
        assert achados
        assert {a.confianca for a in achados} == {"baixa"}

    def test_descricao_anuncia_candidato_e_revisao_manual(self):
        for achado in detectar_arquivo(AMOSTRA_VULNERAVEL):
            assert achado.descricao.startswith(PREFIXO_CANDIDATO)
            assert "revisao manual" in achado.descricao

    def test_descricao_nega_explicitamente_afirmar_vulnerabilidade(self):
        for achado in detectar_arquivo(AMOSTRA_VULNERAVEL):
            assert "NAO afirma vulnerabilidade" in achado.descricao

    def test_recomendacao_distingue_autenticacao_de_autorizacao(self):
        achado = detectar_arquivo(AMOSTRA_VULNERAVEL)[0]
        assert "nao substitui autorizacao" in achado.recomendacao


class TestPadroesDetectados:
    @pytest.mark.parametrize(
        "lookup",
        [
            "Pedido.query.get(item_id)",
            "Pedido.query.get_or_404(item_id)",
            "Pedido.objects.get(pk=item_id)",
            "Pedido.objects.filter(id=item_id)",
            "Pedido.query.filter_by(id=item_id)",
            "get_object_or_404(Pedido, pk=item_id)",
            "session.query(Pedido).get(item_id)",
            "Pedido.objects.filter(pedido_id=item_id)",
        ],
    )
    def test_lookup_por_identificador_vira_candidato(self, lookup):
        assert len(detectar_em_rota(f"    obj = {lookup}")) == 1, lookup

    def test_identificador_vindo_da_query_string_tambem_conta(self):
        achados = detectar(
            '@app.route("/doc")\n'
            "def view():\n"
            "    doc = Documento.query.get(request.args['doc'])\n"
        )
        assert len(achados) == 1

    def test_consulta_sql_filtrada_por_id_vira_candidato(self):
        achados = detectar_em_rota(
            "    cursor.execute('SELECT * FROM contratos WHERE id = ?', (item_id,))"
        )
        assert len(achados) == 1

    def test_cast_para_int_nao_neutraliza_idor(self):
        # int() protege contra injecao, nao contra referencia insegura:
        # o inteiro continua podendo ser o id de outro usuario.
        achados = detectar_em_rota("    obj = Pedido.query.get(int(item_id))")
        assert len(achados) == 1


class TestSupressoes:
    def test_filtro_por_dono_na_consulta_suprime(self):
        achados = detectar_em_rota(
            "    obj = Pedido.query.filter_by(id=item_id, user=current_user).first()"
        )
        assert achados == []

    @pytest.mark.parametrize(
        "campo", ["user_id=current_user.id", "owner=current_user", "created_by=g.user"]
    )
    def test_variacoes_de_filtro_por_dono_suprimem(self, campo):
        achados = detectar_em_rota(f"    obj = Pedido.query.filter_by(id=item_id, {campo})")
        assert achados == [], campo

    def test_decorador_de_autorizacao_suprime(self):
        achados = detectar(
            '@app.route("/r/<item_id>")\n'
            '@permission_required("ver")\n'
            "def view(item_id):\n"
            "    obj = Pedido.query.get(item_id)\n"
        )
        assert achados == []

    def test_login_required_nao_suprime(self):
        # Decisao de projeto: autenticar nao e autorizar.
        achados = detectar(
            '@app.route("/r/<item_id>")\n'
            "@login_required\n"
            "def view(item_id):\n"
            "    obj = Pedido.query.get(item_id)\n"
        )
        assert len(achados) == 1

    def test_consulta_sql_com_filtro_de_dono_suprime(self):
        achados = detectar_em_rota(
            "    cursor.execute('SELECT * FROM c WHERE id = ? AND user_id = ?',"
            " (item_id, current_user.id))"
        )
        assert achados == []

    def test_mencionar_tabela_de_usuarios_nao_suprime(self):
        # Supressao exige COMPARACAO por campo de dono, nao mencao: uma
        # tabela chamada `usuarios` nao pode contar como controle de acesso.
        achados = detectar_em_rota(
            "    cursor.execute('SELECT * FROM usuarios WHERE id = ?', (item_id,))"
        )
        assert len(achados) == 1


class TestAusenciaDeFalsoPositivo:
    def test_amostra_com_controle_de_acesso_nao_gera_candidato(self):
        assert detectar_arquivo(AMOSTRA_SEGURA) == []

    def test_get_em_dicionario_nao_e_lookup(self):
        achados = detectar_em_rota("    valor = CONFIGURACOES.get(item_id)")
        assert achados == []

    def test_lookup_por_campo_que_nao_e_identificador_nao_conta(self):
        achados = detectar_em_rota("    obj = Pedido.query.filter_by(status=item_id)")
        assert achados == []

    def test_identificador_constante_nao_conta(self):
        achados = detectar(
            '@app.route("/r")\ndef view():\n    obj = Pedido.query.get(1)\n'
        )
        assert achados == []

    def test_amostra_de_xss_nao_gera_candidato_de_idor(self):
        caminho = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_xss.py"
        assert detectar_arquivo(caminho) == []


class TestInteracaoEntreCwes:
    def test_query_parametrizada_resolve_sqli_mas_nao_resolve_idor(self):
        """A amostra "segura" de SQLi e segura para CWE-89, nao para CWE-639.

        Parametrizar impede alterar a estrutura da query; nao impede pedir o
        registro de outro usuario. Sao defesas para problemas diferentes.
        """
        caminho = DIRETORIO_AMOSTRAS / "seguro" / "flask_sqli.py"
        candidatos = detectar_arquivo(caminho)
        assert candidatos
        assert {c.confianca for c in candidatos} == {"baixa"}
