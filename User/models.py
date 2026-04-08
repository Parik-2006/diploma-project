from django.db import models

# Create your models here.
class MaliciousBot(models.Model):
    url=models.TextField()
    bot=models.CharField(max_length=90)