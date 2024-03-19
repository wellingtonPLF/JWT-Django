import bcrypt
from django.contrib.auth.hashers import check_password, make_password
from rest_framework import status
from main.subModels.auth import Auth
from main.subModels.token import Token
from main.serializers.authSerializer import AuthSerializer
from rest_framework import viewsets
from rest_framework.exceptions import ParseError
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt import tokens
from main.enum.tokenEnum import TokenEnum
from main.utils.jwtUtil import JwtUtil
from main.enum.jwtEnum import JwtEnum
from main.utils.cookieUtil import CookieUtil
from main.services.tokenService import TokenService
from main.authenticate import AuthAuthentication
from datetime import timedelta

class AuthViewSet(viewsets.ModelViewSet):
    authentication_classes = [AuthAuthentication]
    queryset = Auth.objects.all()
    tokenService = TokenService()
    cookieUtil = CookieUtil()
    jwtUtil = JwtUtil()
    serializer_class = AuthSerializer
    accessTokenName = TokenEnum.TOKEN_NAME.value
    refreshTokenName = TokenEnum.REFRESH_NAME.value

    @action(detail=False, methods=['POST'], url_path='authentication')
    def authenticate(self, request):
        try:
            auth = request.data
            response = Response("Authenticated!")
            if 'email' in auth:
                authDB = Auth.objects.get(email=auth["email"])
            elif "username" in auth:
                authDB = Auth.objects.get(username=auth["username"])
            else:
                raise ParseError("User not Found")
            valid = check_password(auth["password"], authDB.password)
            if not valid:
                raise ParseError("Incorrect Email or Password , try again.")
            jwtToken = self.jwtUtil.generateToken(authDB, TokenEnum.TOKEN_NAME.value)
            refreshToken = self.jwtUtil.generateToken(authDB, TokenEnum.REFRESH_NAME.value)
            jwt = Token(key=jwtToken, auth=authDB)
            self.tokenService.deleteByAuthID(authDB.id)
            self.tokenService.insert(jwt)
            self.cookieUtil.create(response, self.accessTokenName, jwtToken, False, "localhost")
            self.cookieUtil.create(response, self.refreshTokenName, refreshToken, False, "localhost")
            return response
        except Exception as error:
            # raise ParseError(error)
            raise ParseError("Can't Authenticate, credentials not correct.")

    @action(detail=False, methods=['GET'], url_path='testando')
    def testando(self, request):
        response = Response(f"{request.COOKIES}")
        return response

    @action(detail=False, methods=['GET'], url_path='refresh')
    def refresh(self, request):
        response = Response("Refresh!")
        accessToken = self.cookieUtil.getCookieValue(request, self.accessTokenName)
        jwt = self.tokenService.findByToken(accessToken)
        try:
            expiredAcessToken = self.jwtUtil.extractSubject(jwt.key, TokenEnum.TOKEN_NAME.value)
        except:
            expiredAcessToken = None
        if (expiredAcessToken == None):
            refreshToken = self.cookieUtil.getCookieValue(request, self.refreshTokenName)
            if (refreshToken == None):
                raise ParseError(JwtEnum.INVALID_RT.value)
            try:
                authID = self.jwtUtil.extractSubject(refreshToken, TokenEnum.REFRESH_NAME.value)
            except:
                raise ParseError(JwtEnum.EXPIRED_RT.value)
            authDB = Auth.objects.get(id=int(authID))
            jwtToken = self.jwtUtil.generateToken(authDB, TokenEnum.TOKEN_NAME.value)
            jwtRefresh = self.jwtUtil.generateToken(authDB, TokenEnum.REFRESH_NAME.value)
            jwt.key = jwtToken
            self.tokenService.update(jwt)
            self.cookieUtil.create(response, self.accessTokenName, jwtToken, False, "localhost")
            self.cookieUtil.create(response, self.refreshTokenName, jwtRefresh , False, "localhost")
            print("REFRESH!!!!!!")
            return response
        else:
            raise ParseError("Access Token not expired, also can't be refreshed")

    @action(detail=False, methods=['GET'], url_path='logout')
    def logout(self, request):
        response = Response("Logout Successfully!")
        try:
            jwt = self.cookieUtil.getCookieValue(request, self.accessTokenName)
            jwtDB = self.tokenService.findByToken(jwt)
            self.cookieUtil.clear(response, self.accessTokenName)
            self.cookieUtil.clear(response, self.refreshTokenName)
            self.tokenService.delete(jwtDB.id)
            return response
        except:
            raise ParseError("LogOut not accepted")

    @action(detail=False, methods=['GET'], url_path='isLoggedIn')
    def isLoggedIn(self, request):
        jwt  = self.cookieUtil.getCookieValue(request, self.accessTokenName)
        try:
            jwtDB = self.tokenService.findByToken(jwt)
            self.jwtUtil.extractSubject(jwtDB.key, TokenEnum.TOKEN_NAME.value)
        except:
            return Response(False)
        return Response(True)

    @action(detail=False, methods=['GET'], url_path='limitSize')
    def limitSize(self, request):
        qnt = self.get_queryset()
        limit = len(qnt) >= 10
        return Response(limit)

    @action(detail=False, methods=['POST'], url_path='acceptAuth')
    def acceptAuth(self, request):
        auth = request.data
        try:
            authDB = Auth.objects.get(email=auth["email"])
            if(self.tokenService.getTokenValidation(request, authDB.id) == False):
                raise ParseError(JwtEnum.INVALID_USER.value)
            valid = check_password(auth["password"], authDB.password)
            if not valid:
                raise ParseError("Incorrect Password , try again.")
            return Response("Accept Auth!")
        except:
            raise ParseError("Incorrect Email, try again.")

    def create(self, request):
        auth = request.data
        salt = bcrypt.gensalt(10)
        auth["password"]  = make_password(auth["password"], salt=salt, hasher='bcrypt')
        serializer = self.get_serializer(data=auth)
        if serializer.is_valid():
            serializer.save()
            authResponse = {
                "id": serializer.data["id"],
                "username": serializer.data["username"]
            }
            return Response(authResponse)
        return Response(serializer.errors)

    def update(self, request, pk):
        try:
            auth = request.data
            salt = bcrypt.gensalt(10)
            accessToken = self.cookieUtil.getCookieValue(request, self.accessTokenName)
            jwtDB = self.tokenService.findByToken(accessToken)
            authID = self.jwtUtil.extractSubject(jwtDB.key, TokenEnum.TOKEN_NAME.value)
            authDB = Auth.objects.get(id=int(authID))
            if 'password' in auth:
                authDB.password  = make_password(auth["password"], salt=salt, hasher='bcrypt')
            if 'email' in auth:
                authDB.email = auth["email"]
            if 'username' in auth:
                authDB.username = auth["username"]
            authDB.save()
            return Response("Auth Updated")
        except:
            raise ParseError("Something Went Wrong When Updating")

    def destroy (self, request, pk):
        try:
            Auth.objects.get(id=pk).delete()
        except:
            raise ParseError("The requested Auth Id was not found.")
