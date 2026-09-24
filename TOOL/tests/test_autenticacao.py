"""Fase 14: falhas de autenticacao e protecao de credenciais."""

import pytest

from conftest import (
    DIRETORIO_AMOSTRAS,
    linhas_esperadas,
    rodar_detector,
    rodar_detector_em_arquivo,
)
from owaspscan.detectores.autenticacao import (
    DetectorCookieInseguro,
    DetectorExpiracaoDeSessao,
    DetectorHashDeSenhaFraco,
    DetectorJwtSemVerificacao,
    DetectorLoginSemLimite,
    DetectorSenhaEmTextoPuro,
    avaliar_duracao,
)

VULNERAVEL = DIRETORIO_AMOSTRAS / "vulneravel" / "flask_autenticacao.py"
SEGURO = DIRETORIO_AMOSTRAS / "seguro" / "flask_autenticacao.py"

DETECTORES = {
    "CWE-287": DetectorJwtSemVerificacao,
    "CWE-916": DetectorHashDeSenhaFraco,
    "CWE-256": DetectorSenhaEmTextoPuro,
    "CWE-614": DetectorCookieInseguro,
    "CWE-1004": DetectorCookieInseguro,
    "CWE-613": DetectorExpiracaoDeSessao,
    "CWE-307": DetectorLoginSemLimite,
}

OWASP_ESPERADO = {
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-916": "A02:2021 Cryptographic Failures",
    "CWE-256": "A04:2021 Insecure Design",
    "CWE-614": "A05:2021 Security Misconfiguration",
    "CWE-1004": "A05:2021 Security Misconfiguration",
    "CWE-613": "A07:2021 Identification and Authentication Failures",
    "CWE-307": "A07:2021 Identification and Authentication Failures",
}


class TestAmostras:
    @pytest.mark.parametrize("cwe", sorted(DETECTORES))
    def test_vulneravel_bate_com_o_gabarito(self, cwe):
        achados = rodar_detector_em_arquivo(DETECTORES[cwe](), VULNERAVEL)
        linhas = sorted(a.linha for a in achados if a.cwe == cwe)
        assert linhas == linhas_esperadas(VULNERAVEL, cwe)

    @pytest.mark.parametrize("detector", sorted(set(DETECTORES.values()), key=str))
    def test_seguro_nao_tem_achado(self, detector):
        assert rodar_detector_em_arquivo(detector(), SEGURO) == []

    @pytest.mark.parametrize("cwe", sorted(DETECTORES))
    def test_categoria_oficial(self, cwe):
        for achado in rodar_detector_em_arquivo(DETECTORES[cwe](), VULNERAVEL):
            if achado.cwe == cwe:
                assert achado.owasp == OWASP_ESPERADO[cwe]


class TestJwt:
    def detectar(self, chamada):
        return rodar_detector(DetectorJwtSemVerificacao(), f"import jwt\n{chamada}\n")

    @pytest.mark.parametrize(
        "chamada",
        [
            "jwt.decode(t, verify=False)",
            "jwt.decode(t, k, options={'verify_signature': False})",
            "jwt.decode(t, k, algorithms=['NONE'])",
            "jwt.encode(p, None, algorithm='none')",
        ],
    )
    def test_formas_inseguras(self, chamada):
        assert len(self.detectar(chamada)) == 1

    def test_opcoes_em_variavel_sao_resolvidas(self):
        assert len(self.detectar("o = {'verify_signature': False}\njwt.decode(t, options=o)")) == 1

    def test_decode_correto(self):
        assert self.detectar("jwt.decode(t, k, algorithms=['HS256'])") == []

    def test_python_jose(self):
        fonte = "from jose import jwt\njwt.decode(t, k, options={'verify_signature': False})\n"
        assert len(rodar_detector(DetectorJwtSemVerificacao(), fonte)) == 1

    def test_decode_de_outra_coisa_nao_e_jwt(self):
        assert rodar_detector(DetectorJwtSemVerificacao(), "base64.decode(x, verify=False)\n") == []


class TestHashDeSenha:
    def detectar(self, fonte):
        return rodar_detector(DetectorHashDeSenhaFraco(), "import hashlib\n" + fonte)

    @pytest.mark.parametrize(
        "fonte",
        [
            "hashlib.md5(password.encode())\n",
            "hashlib.sha1(user.senha)\n",
            "hashlib.new('md5', pwd)\n",
            "hashlib.sha256(request.form['password'].encode())\n",
        ],
    )
    def test_hash_rapido_em_senha(self, fonte):
        assert [a.confianca for a in self.detectar(fonte)] == ["media"]

    def test_hash_de_conteudo_nao_acusa(self):
        assert self.detectar("hashlib.sha256(arquivo.read())\n") == []

    def test_from_import(self):
        fonte = "from hashlib import md5\nmd5(senha)\n"
        assert len(rodar_detector(DetectorHashDeSenhaFraco(), fonte)) == 1


class TestSenhaEmTextoPuro:
    ROTA = "from flask import request\n@app.post('/x')\ndef v():\n    s = request.form['senha']\n{}\n"

    def detectar(self, corpo):
        return rodar_detector(DetectorSenhaEmTextoPuro(), self.ROTA.format(corpo))

    def test_atribuicao_em_atributo(self):
        assert len(self.detectar("    user.password = s")) == 1

    def test_create_do_orm(self):
        assert len(self.detectar("    User.objects.create(username='a', password=s)")) == 1

    def test_create_user_trata_a_senha(self):
        assert self.detectar("    User.objects.create_user('a', password=s)") == []

    def test_generate_password_hash_neutraliza(self):
        assert self.detectar("    user.password = generate_password_hash(s)") == []

    def test_passlib_hash_neutraliza(self):
        assert self.detectar("    user.password = pwd_context.hash(s)") == []

    def test_variavel_local_nao_e_gravacao(self):
        assert self.detectar("    senha_confirmada = s") == []

    def test_comparacao_em_claro(self):
        achados = self.detectar("    if user.password == s:\n        pass")
        assert [a.confianca for a in achados] == ["media"]

    def test_comparacao_com_literal_nao_e_texto_puro_de_requisicao(self):
        assert self.detectar("    if user.password == 'x':\n        pass") == []


class TestCookies:
    def detectar(self, fonte):
        return rodar_detector(DetectorCookieInseguro(), fonte)

    def test_secure_false_explicito_e_alta(self):
        achados = self.detectar("r.set_cookie('tema', 'x', secure=False, httponly=True)\n")
        assert [(a.cwe, a.confianca) for a in achados] == [("CWE-614", "alta")]

    def test_cookie_sensivel_sem_flags_e_media(self):
        achados = self.detectar("r.set_cookie('sessionid', v)\n")
        assert sorted((a.cwe, a.confianca) for a in achados) == [
            ("CWE-1004", "media"),
            ("CWE-614", "media"),
        ]

    def test_cookie_comum_sem_flags_nao_acusa(self):
        assert self.detectar("r.set_cookie('idioma', 'pt')\n") == []

    def test_configuracao_django(self):
        assert [a.cwe for a in self.detectar("CSRF_COOKIE_SECURE = False\n")] == ["CWE-614"]


class TestExpiracao:
    @pytest.mark.parametrize(
        "expressao,segundos",
        [
            ("3600", 3600),
            ("60 * 60 * 24", 86400),
            ("timedelta(days=2)", 172800),
            ("timedelta(1, 30)", 86430),
            ("datetime.timedelta(weeks=1, hours=1)", 608400),
        ],
    )
    def test_avaliar_duracao(self, expressao, segundos):
        import ast

        assert avaliar_duracao(ast.parse(expressao, mode="eval").body) == segundos

    def test_duracao_nao_literal_nao_e_julgada(self):
        assert rodar_detector(DetectorExpiracaoDeSessao(), "SESSION_COOKIE_AGE = IDADE\n") == []

    def test_sessao_curta_nao_acusa(self):
        fonte = "PERMANENT_SESSION_LIFETIME = timedelta(hours=8)\n"
        assert rodar_detector(DetectorExpiracaoDeSessao(), fonte) == []

    def test_minutos_sao_convertidos(self):
        fonte = "ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7\n"
        assert len(rodar_detector(DetectorExpiracaoDeSessao(), fonte)) == 1


class TestLoginSemLimite:
    def detectar(self, fonte):
        return rodar_detector(DetectorLoginSemLimite(), fonte)

    def test_candidato_honesto(self):
        achados = self.detectar("@app.post('/login')\ndef entrar(): pass\n")
        assert [a.confianca for a in achados] == ["baixa"]
        assert "NAO afirma" in achados[0].descricao

    def test_decorator_de_limite_suprime(self):
        fonte = "@app.post('/login')\n@limiter.limit('5/minute')\ndef entrar(): pass\n"
        assert self.detectar(fonte) == []

    def test_limite_global_suprime(self):
        fonte = (
            "limiter = Limiter(app, default_limits=['100/hour'])\n"
            "@app.post('/login')\ndef entrar(): pass\n"
        )
        assert self.detectar(fonte) == []

    def test_contagem_de_tentativas_suprime(self):
        fonte = "@app.post('/login')\ndef entrar():\n    if user.failed_attempts > 5:\n        abort(429)\n"
        assert self.detectar(fonte) == []

    def test_get_de_login_so_renderiza_formulario(self):
        assert self.detectar("@app.get('/login')\ndef entrar(): pass\n") == []
