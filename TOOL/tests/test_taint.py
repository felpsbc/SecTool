"""Fase 2: catalogo de fontes e motor de taint intraprocedural."""

import ast

import pytest

from owaspscan.analisador import analisar_texto
from owaspscan.motor.catalogo import CATALOGO_PADRAO, Catalogo, FonteDeDados, nome_pontilhado
from owaspscan.motor.taint import analisar_taint, escopo_de


def escopos_de(fonte: str):
    arquivo = analisar_texto(fonte)
    return analisar_taint(arquivo)


def escopo(fonte: str, nome: str = "view"):
    return escopo_de(escopos_de(fonte), nome)


class TestNomePontilhado:
    @pytest.mark.parametrize(
        "codigo, esperado",
        [
            ("request", "request"),
            ("request.args", "request.args"),
            ("request.args.get", "request.args.get"),
            ("self.pedido.dono", "self.pedido.dono"),
            ("f().attr", None),
            ("d['k']", None),
        ],
    )
    def test_reconstroi_cadeia(self, codigo, esperado):
        no = ast.parse(codigo, mode="eval").body
        assert nome_pontilhado(no) == esperado


class TestCatalogo:
    def test_casa_fonte_exata(self):
        assert CATALOGO_PADRAO.fonte_para("request.form").rotulo == "request.form"

    def test_casa_acesso_encadeado(self):
        assert CATALOGO_PADRAO.fonte_para("request.args.get").rotulo == "request.args"

    def test_respeita_fronteira_do_ponto(self):
        assert CATALOGO_PADRAO.fonte_para("request.argsx") is None

    def test_nome_desconhecido_nao_casa(self):
        assert CATALOGO_PADRAO.fonte_para("config.args") is None
        assert CATALOGO_PADRAO.fonte_para(None) is None

    def test_catalogo_padrao_e_flask(self):
        assert CATALOGO_PADRAO.frameworks() == frozenset({"flask"})

    def test_motor_aceita_catalogo_customizado_sem_alterar_o_motor(self):
        catalogo = Catalogo(
            fontes=(FonteDeDados("request.GET", "django", "query string"),)
        )
        arquivo = analisar_texto("def view(request):\n    x = request.GET['id']\n")
        escopos = analisar_taint(arquivo, catalogo=catalogo)
        assert escopo_de(escopos, "view").origens_de("x") == frozenset({"request.GET"})


class TestFontesEPropagacaoBasica:
    def test_acesso_por_indice_contamina(self):
        esc = escopo("def view():\n    x = request.args['id']\n")
        assert esc.esta_contaminado("x")
        assert esc.origens_de("x") == frozenset({"request.args"})

    def test_acesso_por_metodo_get_contamina(self):
        esc = escopo("def view():\n    x = request.args.get('id')\n")
        assert esc.origens_de("x") == frozenset({"request.args"})

    def test_fonte_sem_indice_contamina(self):
        esc = escopo("def view():\n    x = request.form\n")
        assert esc.esta_contaminado("x")

    def test_literal_nao_contamina(self):
        esc = escopo("def view():\n    x = 'SELECT 1'\n    y = 42\n")
        assert not esc.esta_contaminado("x")
        assert not esc.esta_contaminado("y")

    def test_variavel_nao_relacionada_nao_contamina(self):
        esc = escopo("def view():\n    x = request.args['id']\n    y = config.DEBUG\n")
        assert not esc.esta_contaminado("y")

    def test_cadeia_de_atribuicoes_propaga(self):
        esc = escopo(
            "def view():\n"
            "    a = request.args['id']\n"
            "    b = a\n"
            "    c = b\n"
        )
        assert esc.esta_contaminado("c")
        assert esc.origens_de("c") == frozenset({"request.args"})

    def test_duas_fontes_acumulam_origens(self):
        esc = escopo(
            "def view():\n"
            "    a = request.args['id']\n"
            "    b = request.form['nome']\n"
            "    c = a + b\n"
        )
        assert esc.origens_de("c") == frozenset({"request.args", "request.form"})


class TestConstrucaoDeStrings:
    @pytest.mark.parametrize(
        "expressao",
        [
            "'SELECT * FROM u WHERE id = ' + ident",
            "'SELECT * FROM u WHERE id = %s' % ident",
            "'SELECT * FROM u WHERE id = {}'.format(ident)",
            "f'SELECT * FROM u WHERE id = {ident}'",
            "' '.join(['SELECT', ident])",
            "'%s' % (ident,)",
            "str(ident)",
        ],
    )
    def test_montagem_de_string_propaga_taint(self, expressao):
        esc = escopo(
            "def view():\n"
            "    ident = request.args['id']\n"
            f"    consulta = {expressao}\n"
        )
        assert esc.esta_contaminado("consulta"), expressao

    def test_string_montada_so_com_literais_nao_contamina(self):
        esc = escopo(
            "def view():\n"
            "    ident = request.args['id']\n"
            "    consulta = 'SELECT * FROM u WHERE id = ' + '1'\n"
        )
        assert not esc.esta_contaminado("consulta")


class TestEstruturasDeDados:
    def test_desempacotamento_de_tupla_contamina_os_dois(self):
        esc = escopo("def view():\n    a, b = request.args['par'], 1\n")
        assert esc.esta_contaminado("a") and esc.esta_contaminado("b")

    def test_lista_e_dicionario_contaminam(self):
        esc = escopo(
            "def view():\n"
            "    ident = request.args['id']\n"
            "    itens = [ident]\n"
            "    mapa = {'id': ident}\n"
        )
        assert esc.esta_contaminado("itens") and esc.esta_contaminado("mapa")

    def test_indexar_container_contaminado_propaga(self):
        esc = escopo(
            "def view():\n"
            "    itens = [request.args['id']]\n"
            "    primeiro = itens[0]\n"
        )
        assert esc.esta_contaminado("primeiro")

    def test_atribuicao_em_atributo_e_rastreada(self):
        esc = escopo("def view(self):\n    self.consulta = request.args['q']\n")
        assert esc.esta_contaminado("self.consulta")

    def test_compreensao_propaga(self):
        esc = escopo(
            "def view():\n"
            "    ids = [int(i) for i in request.args.getlist('ids')]\n"
        )
        assert esc.esta_contaminado("ids")

    def test_augassign_propaga(self):
        esc = escopo(
            "def view():\n"
            "    consulta = 'SELECT 1'\n"
            "    consulta += request.args['filtro']\n"
        )
        assert esc.esta_contaminado("consulta")

    def test_walrus_propaga(self):
        esc = escopo("def view():\n    if (ident := request.args.get('id')):\n        pass\n")
        assert esc.esta_contaminado("ident")


class TestInsensibilidadeAFluxo:
    def test_taint_em_um_ramo_do_if_conta(self):
        esc = escopo(
            "def view():\n"
            "    ident = '1'\n"
            "    if condicao:\n"
            "        ident = request.args['id']\n"
        )
        assert esc.esta_contaminado("ident")

    def test_taint_atribuido_depois_do_uso_conta(self):
        # Consequencia declarada da regra 2: a ordem textual nao importa.
        esc = escopo(
            "def view():\n"
            "    consulta = 'SELECT ' + ident\n"
            "    ident = request.args['id']\n"
        )
        assert esc.esta_contaminado("consulta")

    def test_taint_dentro_de_laco_propaga(self):
        esc = escopo(
            "def view():\n"
            "    for item in request.form.getlist('itens'):\n"
            "        atual = item\n"
        )
        assert esc.esta_contaminado("item") and esc.esta_contaminado("atual")

    def test_with_propaga(self):
        esc = escopo("def view():\n    with request.files['f'] as arquivo:\n        pass\n")
        assert esc.esta_contaminado("arquivo")


class TestChamadasDesconhecidas:
    def test_retorno_de_funcao_desconhecida_propaga(self):
        esc = escopo(
            "def view():\n"
            "    ident = request.args['id']\n"
            "    consulta = montar_query(ident)\n"
        )
        assert esc.esta_contaminado("consulta")

    def test_metodo_de_valor_contaminado_propaga(self):
        esc = escopo(
            "def view():\n"
            "    ident = request.args['id']\n"
            "    limpo = ident.strip().upper()\n"
        )
        assert esc.esta_contaminado("limpo")

    def test_chamada_sem_argumento_contaminado_nao_propaga(self):
        esc = escopo(
            "def view():\n"
            "    ident = request.args['id']\n"
            "    agora = datetime.now()\n"
        )
        assert not esc.esta_contaminado("agora")


class TestEscopos:
    def test_taint_nao_vaza_entre_funcoes(self):
        escopos = escopos_de(
            "def a():\n"
            "    ident = request.args['id']\n"
            "\n"
            "def b():\n"
            "    consulta = 'SELECT ' + ident\n"
        )
        assert escopo_de(escopos, "a").esta_contaminado("ident")
        assert not escopo_de(escopos, "b").esta_contaminado("ident")
        assert not escopo_de(escopos, "b").esta_contaminado("consulta")

    def test_escopo_de_modulo_existe(self):
        escopos = escopos_de("PADRAO = request.args\n")
        assert escopo_de(escopos, "<modulo>").esta_contaminado("PADRAO")

    def test_metodo_recebe_nome_qualificado(self):
        escopos = escopos_de(
            "class Repositorio:\n"
            "    def buscar(self):\n"
            "        ident = request.args['id']\n"
        )
        assert escopo_de(escopos, "Repositorio.buscar").esta_contaminado("ident")

    def test_funcao_aninhada_herda_taint_do_escopo_externo(self):
        escopos = escopos_de(
            "def externa():\n"
            "    ident = request.args['id']\n"
            "    def interna():\n"
            "        consulta = 'SELECT ' + ident\n"
        )
        assert escopo_de(escopos, "externa.interna").esta_contaminado("consulta")

    def test_parametros_podem_ser_semeados_como_contaminados(self):
        arquivo = analisar_texto(
            "def perfil(user_id):\n    consulta = 'SELECT * FROM u WHERE id=' + user_id\n"
        )
        escopos = analisar_taint(
            arquivo, parametros_contaminados={"perfil": frozenset({"user_id"})}
        )
        assert escopo_de(escopos, "perfil").esta_contaminado("consulta")


class TestOrigensDaExpressao:
    def test_avalia_expressao_arbitraria_no_escopo(self):
        fonte = (
            "def view(cursor):\n"
            "    ident = request.args['id']\n"
            "    cursor.execute('SELECT * FROM u WHERE id = ' + ident)\n"
        )
        esc = escopo(fonte)
        chamada = [
            no
            for no in ast.walk(esc.no)
            if isinstance(no, ast.Call) and getattr(no.func, "attr", None) == "execute"
        ][0]
        argumento = chamada.args[0]
        assert esc.origens_da_expressao(argumento) == frozenset({"request.args"})
        assert esc.expressao_contaminada(argumento)

    def test_expressao_limpa_nao_tem_origens(self):
        esc = escopo("def view(cursor):\n    cursor.execute('SELECT 1')\n")
        chamada = [no for no in ast.walk(esc.no) if isinstance(no, ast.Call)][0]
        assert esc.origens_da_expressao(chamada.args[0]) == frozenset()

    def test_escopo_inexistente_levanta_erro_util(self):
        with pytest.raises(KeyError, match="Disponiveis"):
            escopo_de(escopos_de("def a():\n    pass\n"), "inexistente")
