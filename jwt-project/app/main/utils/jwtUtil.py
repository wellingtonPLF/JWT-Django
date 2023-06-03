
from rest_framework_simplejwt import tokens
from rest_framework_simplejwt import authentication as jwt_authentication
from rest_framework_simplejwt import views as jwt_views
from rest_framework_simplejwt import serializers as jwt_serializers
from rest_framework_simplejwt import exceptions as jwt_exceptions
# import secrets

class JwtUtil(jwt_authentication.JWTAuthentication):
    
    def generateToken(auth, tokenType):
        token = None
        if (tokenType == TokenEnum.TOKEN_NAME):            
            token = tokens.AccessToken.for_user(user)
        elif (tokenType == TokenEnum.REFRESH_NAME):            
            token = tokens.RefreshToken.for_user(user)
        return str(token)

    def extractSubject(key):
        try:
            token = self.get_validated_token(key)
            sub = self.get_user(token)
            return sub
        except:
            raise jwt_exceptions.InvalidToken(
                'Token Expired'
            )
