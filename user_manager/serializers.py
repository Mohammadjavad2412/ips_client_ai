from rest_framework.serializers import ModelSerializer
from user_manager.models import Users

class UserSerializer(ModelSerializer):
    class Meta:
        model = Users
        fields = "__all__"
