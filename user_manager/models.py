from django.db import models
from django.contrib.auth.models import AbstractUser
from user_manager.manager import UserManagement
import uuid
# Create your models here.

class Users(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    username = models.CharField(
        ("username"),
        max_length=150,
        unique=False,
        null=True,
        blank=True
    )
    email = models.EmailField(blank=False, null=False, unique=True)
    password = models.CharField(max_length=100,blank=False, null=False, unique=True)
    is_superuser = models.BooleanField(default=False, blank=True, null=True)

    objects = UserManagement()
     
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password']




