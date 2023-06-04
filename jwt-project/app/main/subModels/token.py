from django.db import models
from main.subModels.auth import Auth

class Token(models.Model):
    key = models.CharField(max_length = 300)
    auth = models.ForeignKey(Auth, on_delete=models.CASCADE)