"""Blueprint com autenticacao centralizada em before_request.

Nenhum candidato a CWE-862: o hook protege todas as rotas do arquivo.
"""

from flask import Blueprint, abort, jsonify
from flask_login import current_user

painel = Blueprint("painel", __name__)


@painel.before_request
def exigir_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@painel.route("/admin/limpar-cache", methods=["POST"])
def limpar_cache():
    return jsonify(ok=True)
