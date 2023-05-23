from django.db import models
from main.models.user import User

class Message(models.Model):
    desc = models.CharField(max_length=200)
    title = models.CharField(max_length=30)
    user = models.ForeignKey(User, on_delete=models.CASCADE)