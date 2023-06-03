from django.db import models
from main.subModels.role import Role

class Auth(models.Model):
    email = models.EmailField(null=False, blank=False, unique=True)
    username = models.CharField(max_length=50, blank=False, null=False)
    password = models.CharField(max_length = 100)
    roles = models.ManyToManyField(Role)