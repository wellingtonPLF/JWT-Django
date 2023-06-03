from django.db import models
from enum import unique
from main.subModels.auth import Auth

class User(models.Model):
    nickname = models.CharField(max_length = 50)
    bornDate = models.DateField()
    auth = models.ForeignKey(Auth, on_delete=models.CASCADE)