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
from main.utils.cookieUtil import CookieUtil
from main.subViews.tokenViewSet import TokenService
from main.authenticate import AuthAuthentication

class AuthViewSet(viewsets.ModelViewSet):
    authentication_classes = [AuthAuthentication]
    queryset = Auth.objects.all()
    tokenService = TokenService()
    serializer_class = AuthSerializer
    accessTokenName = TokenEnum.TOKEN_NAME.value
    refreshTokenName = TokenEnum.REFRESH_NAME.value

    @action(detail=False, methods=['POST'], url_path='authentication')
    def authenticate(self, request):
        try:
            auth = request.data
            res = Response()
            if 'email' in auth:
                authDB = Auth.objects.get(email=auth["email"])
            elif "username" in auth:
                authDB = Auth.objects.get(username=auth["username"])
            else:
                raise rest_exceptions.ParseError("User not Found")
            valid = check_password(auth["password"], authDB.password)
            if not valid:
                raise rest_exceptions.ParseError("Incorrect Email or Password , try again.")
            jwtToken = JwtUtil.generateToken(authDB, TokenEnum.TOKEN_NAME)
            refreshToken = JwtUtil.generateToken(authDB, TokenEnum.REFRESH_NAME)
            jwt = Token(key=jwtToken, auth=authDB)
            self.tokenService.deleteByAuthID(authDB.id)
            self.tokenService.insert(jwt)
            CookieUtil.create(res, self.accessTokenName, jwtToken, False, "localhost")
            CookieUtil.create(res, self.refreshTokenName, refreshToken, False, "localhost")
            return Response("Authenticated!")
        except rest_exceptions.ParseError as e:
            raise rest_exceptions.ParseError("Error occurred:", str(e))

    @action(detail=False, methods=['GET'], url_path='refresh')
    def refresh(self, request):
        res = Response()
        accessToken = CookieUtil.getCookieValue(request, self.accessTokenName)
        jwt = self.tokenService.findByToken(accessToken)
        try:
            expiredAcessToken = JwtUtil.extractSubject(jwt.key)
        except:
            expiredAcessToken = None
        if (expiredAcessToken == None):
            refreshToken = CookieUtil.getCookieValue(request, self.refreshTokenName)
            if (refreshToken == None):
                raise rest_exceptions.ParseError(JwtType.INVALID_RT.value)
            try:
                authID = JwtUtil.extractSubject(refreshToken)
            except:
                raise rest_exceptions.ParseError(JwtType.EXPIRED_RT.value)
            authDB = Auth.objects.get(id=int(authID))
            jwtToken = JwtUtil.generateToken(authDB, TokenEnum.TOKEN_NAME)
            jwtRefresh = JwtUtil.generateToken(authDB, TokenEnum.REFRESH_NAME)
            jwt.key = jwtToken
            self.tokenService.update(jwt)
            CookieUtil.create(res, self.accessTokenName, jwtToken, False, "localhost")
            CookieUtil.create(res, self.refreshTokenName, jwtRefresh , False, "localhost")
        else:
            raise rest_exceptions.ParseError("Access Token not expired, also can't be refreshed")

    @action(detail=False, methods=['GET'], url_path='logout')
    def logout(self, request):
        try:
            res = Response()
            jwt = CookieUtil.getCookieValue(request, self.accessTokenName)
            jwtDB = self.tokenService.findByToken(jwt)
            CookieUtil.clear(res, self.accessTokenName)
            CookieUtil.clear(res, self.refreshTokenName)
            self.tokenService.delete(jwtDB.id)
        except:
            raise rest_exceptions.ParseError("LogOut not accepted")

    @action(detail=False, methods=['GET'], url_path='isLoggedIn')
    def isLoggedIn(self, request):
        jwt  = CookieUtil.getCookieValue(request, self.accessTokenName)
        try:
            jwtDB = self.tokenService.findByToken(jwt)
        except:
            return Response(False)
        JwtUtil.extractSubject(jwtDB.key)
        return Response(True)

    @action(detail=False, methods=['POST'], url_path='acceptAuth')
    def acceptAuth(self, request):
        auth = request.data
        authDB = authRepository.findByEmail(auth.email)
        if(self.tokenService.getTokenValidation(request, authDB.id) == False):
            raise rest_exceptions.ParseError(JwtType.INVALID_USER.value)
        valid = check_password(auth.password, authDB.password)
        if not valid:
            raise rest_exceptions.ParseError("Incorrect Email or Password , try again.")

    def findAll(self):
        users = self.get_queryset()
        serializer = self.get_serializer(users, many=True)
        return serializer.data
    
    def findById(self, auth_id):
        try:
            authDB = Auth.objects.get(id=auth_id)
        except Auth.DoesNotExist:
            raise rest_exceptions.ParseError("The requested Id was not found.")
        serializer = self.get_serializer(authDB)
        return serializer.data
    
    def findByUserID(self, user_id):
        try:
            userDB = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise rest_exceptions.ParseError("Can't find Auth by userID")
        serializer = self.get_serializer(userDB.auth)
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

    def update(self, request):
        auth = request.data
        salt = bcrypt.gensalt(10)
        accessToken = CookieUtil.getCookieValue(request, self.accessTokenName)
        jwtDB = self.tokenService.findByToken(accessToken)
        authID = JwtUtil.extractSubject(jwtDB.key)
        authDB = Auth.objects.get(id=int(authID))
        authDB.password  = make_password(auth.password, salt=salt, hasher='bcrypt')
        if (auth.email != None):
            authDB.email = auth.email
        if (auth.username != None):
            authDB.username = auth.username
            
        serializer = self.get_serializer(data=authDB)

        if serializer.is_valid():
            serializer.save()
            return Response("Auth Updated")
        else:
            raise rest_exceptions.ParseError("Something Went Wrong When Updating")

    def destroy (self, request, pk):
        try:
            self.get_user(pk).delete()
            return Response("Successfully Deletion.",status=status.HTTP_204_NO_CONTENT)
        except:
            return Response("The requested Auth Id was not found.", status=status.HTTP_404_NOT_FOUND)