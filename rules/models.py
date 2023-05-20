from django.db import models
import uuid

# Create your models here.
class Rules(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    rule_name = models.CharField(max_length=20, null=False, blank=False)
