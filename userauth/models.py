from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin
from django.db.models.signals import post_save
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from.manager import UserManager


 

AUTH_PROVIDERS = {'email':'email', 'google':'google'}


class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(unique=True, max_length=100, verbose_name=_("Username"))
    email = models.EmailField(unique=True, max_length=255, verbose_name=_("Email Address"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    auth_provider=models.CharField(max_length=50, default=AUTH_PROVIDERS.get('email'))


    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return{
            'refresh':str(refresh),
            'access':str(refresh.access_token)
        }
    


class OneTimePassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE) 
    otp = models.CharField(max_length=6)  
    created_at = models.DateTimeField(auto_now_add=True) 
    is_used = models.BooleanField(default=False)  

    def __str__(self):
        return f"{self.user.username} - {self.otp}"

    def is_expired(self):
        expiration_time = self.created_at + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
        return timezone.now() > expiration_time

    