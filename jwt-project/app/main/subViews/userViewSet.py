from rest_framework import status
from main.subModels.user import User
from main.subModels.auth import Auth
from main.serializers.userSerializer import UserSerializer
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt import tokens
from main.enum.tokenEnum import TokenEnum
from main.utils.jwtUtil import JwtUtil
from main.utils.cookieUtil import CookieUtil
from main.subViews.authViewSet import AuthViewSet
from main.subViews.tokenViewSet import TokenService
from main.authenticate import UserAuthentication

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    authentication_classes = [UserAuthentication]
    authService = AuthViewSet()
    tokenService = TokenService()
    serializer_class = UserSerializer
    accessTokenName = TokenEnum.TOKEN_NAME.value
    refreshTokenName = TokenEnum.REFRESH_NAME.value

    def list(self, request):
        users = self.get_queryset()
        serializer = self.get_serializer(users, many=True)
        return Response(serializer.data)

    #detail=True => /users/{id}/testando/
    #detail=False => /users/testando/
    @action(detail=False, methods=['GET'], url_path='getUser')
    def getAuthenticatedUser(self, request):
        accessToken = CookieUtil.getCookieValue(request, self.accessTokenName)
        jwt = self.tokenService.findByToken(accessToken)
        authID = JwtUtil.extractSubject(jwt.key)
        authDB = Auth.objects.get(id=int(authID))
        try:
            userDB = User.objects.get(auth_id=authDB.id)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(userDB)
        return Response(serializer.data)

    def create(self, request):
        data = request.data
        auth_id = data.get("auth_id")
        auth = Auth.objects.get(id=auth_id) if auth_id else None

        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            serializer.save(auth=auth)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)

    def update(self, request):
        user = request.data
        userDB = User.objects.get(id=user.id)

        if user == None:
            raise rest_exceptions.ParseError(JwtType.INVALID_USER.value)
        authDB = self.authService.findByUserID(user.id)

        if self.tokenService.getTokenValidation(authDB.id, request) == false:
            raise rest_exceptions.ParseError(JwtType.INVALID_USER.value)

        user.auth = authDB
        serializer = self.get_serializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors)

    def destroy (self, request, response, pk):
        if pk == None:
            raise rest_exceptions.ParseError("UserId is null")
		
        auth = self.authService.findByUserID(pk)
        if(self.tokenService.getTokenValidation(auth.id, request) == false):
            raise rest_exceptions.ParseError(JwtType.INVALID_USER.toString())
        self.get_user(pk).delete()
        CookieUtil.clear(response, self.accessTokenName)
        CookieUtil.clear(response, self.refreshTokenName)
        return Response("Successfully Deletion.",status=status.HTTP_204_NO_CONTENT)