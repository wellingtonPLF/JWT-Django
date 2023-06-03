from rest_framework import routers
from main.views.userViewSet import UserViewSet
from main.views.authViewSet import AuthViewSet

router = routers.DefaultRouter()
router.register(r'user', UserViewSet)
router.register(r'auth', AuthViewSet)