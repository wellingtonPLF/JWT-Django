from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AuthAuthentication(BaseAuthentication):
    def authenticate(self, request):
        method = request.method

        if method == "GET" and "/isLoggedIn/" in request.path:
            return None
        elif method == "GET" and "/refresh" in request.path:
            return None
        elif method == "GET" and "/logout" in request.path:
            return None
        elif method == "POST" and "/authentication" in request.path:
            return None
        elif method == "POST" and "/" in request.path:
            return None
        else:
            return None
            # raise AuthenticationFailed('Access denied.')

class UserAuthentication(BaseAuthentication):
    def authenticate(self, request):
        method = request.method

        if method == "GET" and "/getUser/" in request.path:
            return None
        else:
            return None
            # raise AuthenticationFailed('Access denied.')
