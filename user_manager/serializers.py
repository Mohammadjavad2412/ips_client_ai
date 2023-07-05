from rest_framework.serializers import ModelSerializer
from user_manager.models import Users
from rest_framework import serializers
from ips_client import settings


class UserSerializer(ModelSerializer):

    device_serial = serializers.SerializerMethodField()

    class Meta:
        model = Users
        fields = "__all__"

    def create(self, validated_data):
        password = validated_data.pop('password')
        if validated_data['is_admin'] == True:
            validated_data['is_analyser'] = True
        else:
            pass
        instance = self.Meta.model(**validated_data)
        instance.set_password(password)
        
        instance.save()
        return instance
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        same_password_sent = instance.check_password(password)
        if same_password_sent:
            raise serializers.ValidationError({"error": "try another password"})
        else:
            instance.set_password(password)
            return super().update(instance, validated_data)
        
    def get_device_serial(self, obj):
        return settings.DEVICE_SERIAL


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

