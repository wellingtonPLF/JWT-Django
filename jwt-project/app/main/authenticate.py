from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from main.enum.roleEnum import RoleEnum
from main.services.authService import AuthService

class AuthAuthentication(BaseAuthentication):
    authService = AuthService()

    def authenticate(self, request):
        method = request.method
        
        if method == "POST" and "/authentication" in request.path:
            return None
        elif method == "GET" and "/isLoggedIn" in request.path:
            return None
        elif method == "POST" and "/" in request.path:
            return None
        elif method == "GET" and "/refresh" in request.path:
            return None
        elif method == "GET" and "/testando" in request.path:
            return None
        elif method == "GET" and "/logout" in request.path:
            return None
        elif method == "GET" and "/limitSize" in request.path:
            return None
        else:
            roleList = self.authService.getRoles(request)
            if method == "GET" and "/" in request.path:
                if RoleEnum.ROLE_ADMIN.value in roleList:
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            elif method == "POST" and "/acceptAuth" in request.path:
                if any(role.value in roleList for role in RoleEnum):
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            elif method == "PUT" and "/" in request.path:
                if any(role.value in roleList for role in RoleEnum):
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            elif method == "DELETE" and "/" in request.path:
                if RoleEnum.ROLE_ADMIN.value in roleList:
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            else:
                raise AuthenticationFailed('Access denied.')

class UserAuthentication(BaseAuthentication):
    authService = AuthService()
    
    def authenticate(self, request):
        method = request.method

        if method == "POST" and "/" in request.path:
            return None
        else:
            roleList = self.authService.getRoles(request)
            if method == "GET" and "/" in request.path:
                if any(role.value in roleList for role in RoleEnum):
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            if method == "PUT" and "/" in request.path:
                if any(role.value in roleList for role in RoleEnum):
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            elif method == "DELETE" and "/" in request.path:
                if any(role.value in roleList for role in RoleEnum):
                    return None
                else:
                    raise AuthenticationFailed('Access denied.')
            else:
                raise AuthenticationFailed('Access denied.')
            
            # IF you Want to apply Both roles use code below:
            #
            # if all(role_id in [role.value for role in RoleEnum] for role_id in roleList):
            #     return None
            # else:
            #     raise AuthenticationFailed('Access denied.')
