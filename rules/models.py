from django.db import models
from user_manager.models import Users
from django.core.validators import validate_ipv46_address
import uuid

# Create your models here.
class Rules(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    rule_name = models.CharField(max_length=20, null=False, blank=False)
    rule_code = models.TextField(null=True, blank=True)
    creator = models.ForeignKey(Users, on_delete=models.DO_NOTHING, null=False, blank=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update_at = models.DateTimeField(auto_now=True, null=True, blank=True)


class ValidIps(models.Model):
    TYPE_CHOICES = (("Internal", "Internal"), ("External", "External"))
    ip_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    ip = models.CharField(max_length= 32,null=True, blank=True)
    
    class Meta:
        unique_together = ('ip', 'ip_type')
        