
from rest_framework_simplejwt import tokens
from rest_framework_simplejwt import authentication as jwt_authentication
from rest_framework_simplejwt import views as jwt_views
from main.enum.tokenEnum import TokenEnum
from rest_framework_simplejwt import serializers as jwt_serializers
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.tokens import RefreshToken
# import secrets

class JwtUtil(jwt_authentication.JWTAuthentication):
    
    def generateToken(self, auth, tokenType):
        token = None
        if (tokenType == TokenEnum.TOKEN_NAME):
            token = tokens.AccessToken.for_user(auth)
        elif (tokenType == TokenEnum.REFRESH_NAME):
            token = tokens.RefreshToken.for_user(auth)
        return str(token)

    def extractSubject(self, key, tokenType):
        try:
            if (tokenType == TokenEnum.TOKEN_NAME):
                token = self.get_validated_token(key)
            elif (tokenType == TokenEnum.REFRESH_NAME):
                token = RefreshToken(key)
                if token['exp'] < token['iat']:
                    raise InvalidToken('Token Expired')
            user_id = token['user_id']
            return user_id
        except:
            raise InvalidToken('Token Expired')

        