import bcrypt
from django.contrib.auth.hashers import check_password, make_password
from rest_framework import status
from main.subModels.auth import Auth
from main.subModels.user import User
from main.subModels.token import Token
from main.serializers.authSerializer import AuthSerializer
from rest_framework import viewsets, exceptions as rest_exceptions
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
                raise rest_exceptions.ParseError("User not Found")
            valid = check_password(auth["password"], authDB.password)
            if not valid:
                raise rest_exceptions.ParseError("Incorrect Email or Password , try again.")
            jwtToken = self.jwtUtil.generateToken(authDB, TokenEnum.TOKEN_NAME)
            refreshToken = self.jwtUtil.generateToken(authDB, TokenEnum.REFRESH_NAME)
            jwt = Token(key=jwtToken, auth=authDB)
            self.tokenService.deleteByAuthID(authDB.id)
            self.tokenService.insert(jwt)
            self.cookieUtil.create(response, self.accessTokenName, jwtToken, False, "localhost")
            self.cookieUtil.create(response, self.refreshTokenName, refreshToken, False, "localhost")
            return response
        except:
            raise rest_exceptions.ParseError("Can't Authenticate, credentials not correct.")

    @action(detail=False, methods=['GET'], url_path='refresh')
    def refresh(self, request):
        response = Response("Refresh!")
        accessToken = self.cookieUtil.getCookieValue(request, self.accessTokenName)
        jwt = self.tokenService.findByToken(accessToken)
        try:
            expiredAcessToken = self.jwtUtil.extractSubject(jwt.key, TokenEnum.TOKEN_NAME)
        except:
            expiredAcessToken = None
        if (expiredAcessToken == None):
            refreshToken = self.cookieUtil.getCookieValue(request, self.refreshTokenName)
            if (refreshToken == None):
                raise rest_exceptions.ParseError(JwtEnum.INVALID_RT.value)
            try:
                authID = self.jwtUtil.extractSubject(refreshToken, TokenEnum.REFRESH_NAME)
            except:
                raise rest_exceptions.ParseError(JwtEnum.EXPIRED_RT.value)
            authDB = Auth.objects.get(id=int(authID))
            jwtToken = self.jwtUtil.generateToken(authDB, TokenEnum.TOKEN_NAME)
            jwtRefresh = self.jwtUtil.generateToken(authDB, TokenEnum.REFRESH_NAME)
            jwt.key = jwtToken
            self.tokenService.update(jwt)
            self.cookieUtil.create(response, self.accessTokenName, jwtToken, False, "localhost")
            self.cookieUtil.create(response, self.refreshTokenName, jwtRefresh , False, "localhost")
            return response
        else:
            raise rest_exceptions.ParseError("Access Token not expired, also can't be refreshed")

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
            raise rest_exceptions.ParseError("LogOut not accepted")

    @action(detail=False, methods=['GET'], url_path='isLoggedIn')
    def isLoggedIn(self, request):
        jwt  = self.cookieUtil.getCookieValue(request, self.accessTokenName)
        try:
            jwtDB = self.tokenService.findByToken(jwt)
        except:
            return Response(False)
        self.jwtUtil.extractSubject(jwtDB.key, TokenEnum.TOKEN_NAME)
        return Response(True)

    @action(detail=False, methods=['POST'], url_path='acceptAuth')
    def acceptAuth(self, request):
        auth = request.data
        try:
            authDB = Auth.objects.get(email=auth["email"])
            if(self.tokenService.getTokenValidation(request, authDB.id) == False):
                raise rest_exceptions.ParseError(JwtEnum.INVALID_USER.value)
            valid = check_password(auth["password"], authDB.password)
            if not valid:
                raise rest_exceptions.ParseError("Incorrect Password , try again.")
            return Response("Accept Auth!")
        except:
            raise rest_exceptions.ParseError("Incorrect Email, try again.")

    def findAll(self):
        users = self.get_queryset()
        serializer = self.get_serializer(users, many=True)
        return serializer.data
    
    def findById(self, auth_id):
        try:
            authDB = Auth.objects.get(id=auth_id)
        except Auth.DoesNotExist:
            raise rest_exceptions.ParseError("The requested Id was not found.")        
        serializer = AuthSerializer(instance=authDB)
        return serializer.data
    
    def findByUserID(self, user_id):
        try:
            userDB = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise rest_exceptions.ParseError("Can't find Auth by userID")
        serializer = AuthSerializer(instance=userDB.auth)
        return serializer.data

    def create(self, request):
        auth = request.data
        salt = bcrypt.gensalt(10)
        auth["password"]  = make_password(auth["password"], salt=salt, hasher='bcrypt')
        serializer = self.get_serializer(data=auth)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors)

    def update(self, request, pk):
        try:
            auth = request.data
            salt = bcrypt.gensalt(10)
            accessToken = self.cookieUtil.getCookieValue(request, self.accessTokenName)
            jwtDB = self.tokenService.findByToken(accessToken)
            authID = self.jwtUtil.extractSubject(jwtDB.key, TokenEnum.TOKEN_NAME)
            authDB = Auth.objects.get(id=int(authID))
            authDB.password  = make_password(auth["password"], salt=salt, hasher='bcrypt')
            if 'email' in auth:
                authDB.email = auth["email"]
            if 'username' in auth:
                authDB.username = auth["username"]
            authDB.save()
            return Response("Auth Updated")
        except:
            raise rest_exceptions.ParseError("Something Went Wrong When Updating")

    def destroy (self, request, pk):
        try:
            Auth.objects.get(id=pk).delete()
            return Response("Successfully Deletion.",status=status.HTTP_204_NO_CONTENT)
        except:
            raise rest_exceptions.ParseError("The requested Auth Id was not found.")