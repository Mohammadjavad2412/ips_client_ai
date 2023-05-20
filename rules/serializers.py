from rest_framework.serializers import ModelSerializer
from .models import Rules

class RulesSerializers(ModelSerializer):
    class Meta:
        model = Rules
        fields = "__all__"
        read_only_fields = ('id', 'rule_name')
