from django.db import models
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin,BaseUserManager
from django.utils import timezone

from django.conf import settings
import random
from datetime import timedelta

class CustomUserManager(BaseUserManager):
    def create_user(self,username,email,password=None,**extra_fields):
        if not  username:
            raise ValueError('username not required')
        if not email:
            raise ValueError('email not required')
        email=self.normalize_email(email)
        user=self.model(username=username,email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self,username,email,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)

        return self.create_user(username,email,password,**extra_fields)
    
class User(AbstractBaseUser,PermissionsMixin)    :
    username=models.CharField(max_length=100,unique=True)
    email=models.EmailField(unique=True)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    role=models.CharField(max_length=100,default='Developer')
    date_joined=models.DateTimeField(default=timezone.now)

    objects=CustomUserManager()

    USERNAME_FIELD='username'
    REQUIRED_FIELDS=['email']

    def __str__(self):
        return self.username


class OTP(models.Model):
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    code=models.CharField(max_length=6)
    created_at=models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at +timedelta(minutes=10)
    def __str__(self):
        return f" OTP for {self.user.username} - {self.code}"