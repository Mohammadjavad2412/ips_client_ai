from rest_framework.fields import empty
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from .models import Rules, ValidIps
from user_manager.serializers import UserSerializer
from utils.functions import sync_db_and_snort, retrieve_rule
from ips_client import settings
import ipaddress
import logging
import traceback


class RulesSerializers(ModelSerializer):
    creator = UserSerializer(required=False)

    class Meta:
        model = Rules
        fields = "__all__"
        read_only_fields = ('creator', 'rule_name')

    def create(self, validated_data):
        pk = validated_data['id']
        rule_detail = retrieve_rule(pk)
        rule_name = rule_detail['name']
        rule_code = rule_detail['code']
        description = rule_detail['description']
        version = rule_detail['version']
        user = self.context['request'].user
        validated_data['rule_name'] = rule_name
        validated_data['rule_code'] = rule_code
        validated_data['description'] = description
        validated_data['version'] = version
        validated_data['creator'] = user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        id = instance.i
        rule_detail = retrieve_rule(id)
        version = rule_detail['version']
        validated_data['version'] =version
        return super().update(instance, validated_data)

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
            sync_db_and_snort()
            return ip
        except:
            logging.error(traceback.format_exc())
            raise serializers.ValidationError({"error": "somthing's wrong"})

    def update(self, instance, validated_data):
        try:
            super().update(instance, validated_data)
            sync_db_and_snort()
            return instance
        except:
            logging.error(traceback.format_exc())
            raise serializers.ValidationError({"error": "somthing's wrong"})
