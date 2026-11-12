"""TEMPORARY auth diagnostics (remove once the Vercel logout issue is resolved).

Records *why* an incoming session is not authenticated and, when the request ends in a
redirect (e.g. @login_required bouncing to the login card), shows that reason in the
flash message so it can be reported without server-log access. No secrets are exposed.
"""
import os

from django.contrib import messages
from django.contrib.auth import get_user_model


class AuthDiagBefore:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        reason = None
        try:
            sess = request.session
            uid = sess.get('_auth_user_id')
            has_cookie = 'sessionid' in request.COOKIES
            if uid:
                User = get_user_model()
                user = User.objects.filter(pk=uid).first()
                if user is None:
                    reason = f'user-id-{uid}-missing-in-this-instance-db (users={User.objects.count()})'
                elif sess.get('_auth_user_hash') != user.get_session_auth_hash():
                    reason = 'password-hash-mismatch'
            elif has_cookie and request.path not in ('/', '/login/', '/admin-portal/login/'):
                reason = 'sessionid-cookie-present-but-no-login-in-it'
            elif not has_cookie and request.path not in ('/', '/login/', '/admin-portal/login/'):
                reason = 'browser-sent-no-sessionid-cookie'
        except Exception as exc:  # never break the request because of diagnostics
            reason = f'diag-error-{type(exc).__name__}'
        request._ua_diag = reason
        return self.get_response(request)


class AuthDiagAfter:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        reason = getattr(request, '_ua_diag', None)
        if reason and response.status_code == 302 and hasattr(request, '_messages'):
            messages.warning(request, f'[diag] {request.path} -> {reason} (pid {os.getpid()})')
        return response

