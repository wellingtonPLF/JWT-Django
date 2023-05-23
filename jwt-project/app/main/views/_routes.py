from rest_framework import routers
from .userViewSet import UserViewSet
from .messageViewSet import MessageViewSet

router = routers.DefaultRouter()
router.register(r'user', UserViewSet)
router.register(r'message', MessageViewSet)