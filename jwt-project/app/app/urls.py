from django.contrib import admin
from rest_framework import routers
from django.urls import include, path, re_path
from main.views._routes import router

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^', include(router.urls)),
    # re_path(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework '))
]