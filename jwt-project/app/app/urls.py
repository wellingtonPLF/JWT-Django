from django.contrib import admin
from rest_framework import routers
from django.urls import include, path, re_path
from main.views._routes import router
from main.views.userViewSet import UserViewSet

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^', include(router.urls)),
    # re_path(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework '))

    # path('login', views.loginView),
    # path('register', views.registerView),
    # path('refresh-token', views.CookieTokenRefreshView.as_view()),
    # path('logout', views.logoutView),
    # path("user", views.user),
]