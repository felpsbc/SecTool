"""Amostra Django sem protecao CSRF (gabarito inline). Nao executar."""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

MIDDLEWARE = [  # achado: CWE-352
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]


@csrf_exempt  # achado: CWE-352
@login_required
def alterar_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return JsonResponse({"ok": True})
