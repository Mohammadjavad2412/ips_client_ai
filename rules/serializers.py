from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from .models import Rules, ValidIps
from utils.functions import sync_db_snort_ips
import ipaddress
import logging
import traceback


class RulesSerializers(ModelSerializer):
    class Meta:
        model = Rules
        fields = "__all__"
        read_only_fields = ('id', 'rule_name', 'creator', 'ip_list')
    
    def save(self, **kwargs):
        user = self.context['request'].user
        self.creator = user
        return super().save(**kwargs)
    
class IpSerializers(ModelSerializer):
    class Meta:
        model = ValidIps
        fields = "__all__"
    

    def validate_ip(self, data):
        ip = data
        try:
            ipaddress.ip_address(ip)
            return data
        except:
            raise serializers.ValidationError(f"ip {ip} is not valid")

    def create(self, validated_data):
        try:
            ip = ValidIps.objects.create(**validated_data)
            sync_db_snort_ips()
            return ip
        except:
            logging.error(traceback.format_exc())
            raise serializers.ValidationError({"error": "somthing's wrong"})

    def update(self, instance, validated_data):
        try: 
            super().update(instance, validated_data)
            sync_db_snort_ips()
            return instance
        except:
            logging.error(traceback.format_exc())
            raise serializers.ValidationError({"error": "somthing's wrong"})

