from rest_framework.fields import empty
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from .models import Rules, InValidIps
from user_manager.serializers import UserSerializer
from rest_framework.response import Response
from rest_framework import status
from utils.functions import sync_db_and_snort, retrieve_rule, is_equal_code
from ips_client import settings
import ipaddress
import logging
import traceback
import re


class RulesSerializers(ModelSerializer):
    creator = UserSerializer(required=False)
    without_action_code = serializers.JSONField()
    class Meta:
        model = Rules
        fields = "__all__"
        read_only_fields = ('creator', 'rule_name')

    def create(self, validated_data):
        pk = validated_data['id']
        rule_detail = retrieve_rule(pk)
        rule_code = rule_detail['code']
        if 'rule_code' in validated_data:
            recieved_rule = validated_data['rule_code']
            is_equal = is_equal_code(recieved_rule, rule_code)
            if is_equal:
                validated_data['rule_code'] = recieved_rule
            else:
                raise serializers.ValidationError("codes in rules is different",code=400)
        else:
            validated_data['rule_code'] = rule_code
        rule_name = rule_detail['name']
        description = rule_detail['description']
        version = rule_detail['version']
        user = self.context['request'].user
        validated_data['rule_name'] = rule_name
        validated_data['description'] = description
        validated_data['version'] = version
        validated_data['creator'] = user
        return super().create(validated_data)


    def update(self, instance, validated_data):
        id = instance.id
        recieved_rule = validated_data['rule_code']
        rule_detail = retrieve_rule(id)
        server_rule_code = rule_detail['code']
        try:
            rule_code = Rules.objects.get(id=id).rule_code
        except:
            raise serializers.ValidationError("maybe rule id has been changed or deleted",code=400)
        version = rule_detail['version']
        validated_data['version'] =version
        is_equal_my_db = is_equal_code(recieved_rule, rule_code)
        is_equal_server = is_equal_code(recieved_rule, server_rule_code)
        if is_equal_my_db or is_equal_server:
            validated_data['rule_code'] = recieved_rule
            return super().update(instance, validated_data)
        else:
            return serializers.ValidationError("codes in rules is different")

class IpSerializers(ModelSerializer):
    class Meta:
        model = InValidIps
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
            ip = InValidIps.objects.create(**validated_data)
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
