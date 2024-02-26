from django.db import models
from django.utils import timezone
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin
)
from .managers import UserManager


# Create your models here.

class User(AbstractBaseUser, PermissionsMixin):

    email = models.EmailField(max_length=40, unique=True)
    username =models.CharField(max_length=40)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']


    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)
        return self
    

class Profile(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    image = models. ImageField(default='user.jpg', upload_to='user_profile')
    phone_number = models.CharField(max_length=11)
    date_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.user.username} profile'

