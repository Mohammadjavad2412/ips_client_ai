from django.db import models
from user_manager.models import Users
from django.core.validators import validate_ipv46_address
import uuid

# Create your models here.
class Rules(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    rule_name = models.CharField(max_length=20, null=False, blank=False)
    creator = models.ForeignKey(Users, on_delete=models.DO_NOTHING, null=False, blank=False)

class ValidIps(models.Model):
    TYPE_CHOICES = (("Internal", "Internal"), ("External", "External"))
    ip_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    ip = models.CharField(max_length= 32,null=True, blank=True, unique=True)
        