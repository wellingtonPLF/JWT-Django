from rest_framework import status
from main.subModels.auth import Auth
from main.subModels.user import User
from main.subModels.token import Token
from main.serializers.authSerializer import AuthSerializer
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework_simplejwt import tokens
from main.enum.tokenEnum import TokenEnum
from main.utils.jwtUtil import JwtUtil
from main.utils.cookieUtil import CookieUtil
from main.views.tokenViewSet import TokenViewSet
from django.contrib.auth.hashers import check_password, make_password

class AuthViewSet(viewsets.ModelViewSet):
    queryset = Auth.objects.all()
    tokenService = TokenViewSet()
    serializer_class = AuthSerializer
    accessTokenName = TokenEnum.TOKEN_NAME.value
    refreshTokenName = TokenEnum.REFRESH_NAME.value

    @action(detail=False, methods=['POST'], url_path='authentication')
    def authenticate(self, request, response):
        try:
            auth = request.data
            if (auth.email != None):
                authDB = Auth.objects.get(email=auth.email)
            elif (auth.username != None):
                authDB = Auth.objects.get(username=auth.username)
            else:
                raise rest_exceptions.ParseError("User not Found")
            valid = check_password(auth.password, authDB.password)
            if not valid:
                raise rest_exceptions.ParseError("Incorrect Email or Password , try again.")

            jwtToken = JwtUtil.generateToken(authDB, TokenType.ACCESS_TOKEN)
            refreshToken = JwtUtil.generateToken(authDB, TokenType.REFRESH_TOKEN)

            jwt = Token(key=jwtToken, auth=authDB)

            self.tokenService.deleteByAuthID(authDB.id)
            self.tokenService.insert(jwt)
            CookieUtil.create(response, this.accessTokenName, jwtToken, false, "localhost")
            CookieUtil.create(response, this.refreshTokenName, refreshToken, false, "localhost")
        except:
            raise rest_exceptions.ParseError("Can't Authenticate")

    @action(detail=False, methods=['GET'], url_path='refresh')
    def refresh(self, request, response):
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
            jwtToken = JwtUtil.generateToken(authDB, TokenType.ACCESS_TOKEN)
            jwtRefresh = JwtUtil.generateToken(authDB, TokenType.REFRESH_TOKEN)
            jwt.key = jwtToken
            self.tokenService.update(jwt)
            CookieUtil.create(response, self.accessTokenName, jwtToken, false, "localhost")
            CookieUtil.create(response, self.refreshTokenName, jwtRefresh , false, "localhost")
        else:
            raise rest_exceptions.ParseError("Access Token not expired, also can't be refreshed")

    @action(detail=False, methods=['GET'], url_path='logout')
    def logout(self, request, response):
        try:
            jwt = CookieUtil.getCookieValue(request, self.accessTokenName)
            jwtDB = self.tokenService.findByToken(jwt)
            CookieUtil.clear(response, self.accessTokenName)
            CookieUtil.clear(response, self.refreshTokenName)
            self.tokenService.delete(jwtDB.id)
        except:
            raise rest_exceptions.ParseError("LogOut not accepted")

    @action(detail=False, methods=['GET'], url_path='isLoggedIn')
    def isLoggedIn(self, request):
        jwt  = CookieUtil.getCookieValue(request, self.accessTokenName)
        try:
            jwtDB = self.tokenService.findByToken(jwt)
        except:
            return false
        JwtUtil.extractSubject(jwtDB.key)
        return true

    @action(detail=False, methods=['POST'], url_path='acceptAuth')
    def acceptAuth(self, request, response):
        auth = request.data
        authDB = authRepository.findByEmail(auth.email)
        if(self.tokenService.getTokenValidation(request, authDB.id) == false):
            raise rest_exceptions.ParseError(JwtType.INVALID_USER.value)
        valid = check_password(auth.password, authDB.password)
        if not valid:
            raise rest_exceptions.ParseError("Incorrect Email or Password , try again.")

    def findAll(self):
        users = self.get_queryset()
        serializer = self.get_serializer(users, many=True)
        return Response(serializer.data)
    
    def findById(self, auth_id):
        try:
            authDB = Auth.objects.get(id=auth_id)
        except Auth.DoesNotExist:
            return Response("The requested Id was not found.", status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(authDB)
        return Response(serializer.data)
    
    def findByUserID(self, user_id):
        try:
            userDB = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response("Can't find Auth by userID.", status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(userDB.auth)
        return Response(serializer.data)

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors)

    def update(self, request):
        auth = request.data
        accessToken = CookieUtil.getCookieValue(request, self.accessTokenName)
        jwtDB = self.tokenService.findByToken(accessToken)
        authID = JwtUtil.extractSubject(jwtDB.key)
        authDB = Auth.objects.get(id=int(authID))
        authDB.password  = make_password(auth.password, salt=10, hasher='bcrypt')
        if (auth.email != None):
            authDB.email = auth.email
        if (auth.username != None):
            authDB.username = auth.username
            
        serializer = self.get_serializer(data=authDB)

        if serializer.is_valid():
            serializer.save()
        else:
            raise rest_exceptions.ParseError("Something Went Wrong When Updating")

    def destroy (self, request, pk):
        try:
            self.get_user(pk).delete()
            return Response("Successfully Deletion.",status=status.HTTP_204_NO_CONTENT)
        except:
            return Response("The requested Auth Id was not found.", status=status.HTTP_404_NOT_FOUND)