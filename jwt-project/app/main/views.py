from rest_framework import routers
from main.subViews.userViewSet import UserViewSet
from main.subViews.authViewSet import AuthViewSet

router = routers.DefaultRouter()
router.register(r'user', UserViewSet)
router.register(r'auth', AuthViewSet)