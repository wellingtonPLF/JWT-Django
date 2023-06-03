from django.db import models

class Role(models.Model):
    roleName = models.CharField(max_length = 50)