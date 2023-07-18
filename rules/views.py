from .models import Rules, InValidIps
from user_manager.models import Users
from .serializers import RulesSerializers, IpSerializers
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status
from .models import Rules
from ips_client.settings import BASE_DIR
from utils.functions import (
    get_rules_list,
    retrieve_rule,
    change_mod,
    set_snort_conf,
    delete_rule_file,
    get_access_token_from_server,
    set_device_serial,
    # sync_db_snort_ips,
    restart_snort,
    sync_db_and_snort
)
from ips_client import settings
from user_manager.permissions import IsAdmin
from rest_framework import generics
from django.shortcuts import get_object_or_404
import logging
import traceback
import requests
import json
import os

# Create your views here.


class RulesView(ModelViewSet):
    queryset = Rules.objects.all()
    serializer_class = RulesSerializers
    permission_classes = [IsAdmin]

    def perform_update(self, serializer):
        super().perform_update(serializer)
        sync_db_and_snort()


    def perform_create(self, serializer):
        try:
            super().perform_create(serializer)
            sync_db_and_snort()
        except:
            logging.error(traceback.format_exc())
    def perform_destroy(self, instance):
        super().perform_destroy(instance)
        sync_db_and_snort()


class RulesList(APIView):
    """
    get list of rules or filtered rules by action.
    """
    permission_classes = [IsAdmin]
    def get(self, request):
        language = request.META.get("HTTP_ACCEPT_LANGUAGE")
        params = request.query_params
        rules_list = get_rules_list(language, params)
        if rules_list:
            return Response(rules_list, status.HTTP_200_OK)
        if rules_list == []:
            return Response({"info": "currently there is no rules available"}, status.HTTP_200_OK)
        else:
            return Response({'error': 'you have not been authorized in server side'}, status.HTTP_407_PROXY_AUTHENTICATION_REQUIRED)

class DisableRule(APIView):
    """
    disable a specific rule.
    """  
    permission_classes = [IsAdmin]
    def get(self, request, rule_name):
        try:
            rule = Rules.objects.get(rule_name=rule_name)
            rule.delete()
            set_snort_conf()
            delete_rule_file(rule_name)
            restart_snort()
            return Response({"info": "rule deleted successfully"}, status.HTTP_200_OK)
        except:
            return Response({"error": "invalid name"}, status.HTTP_400_BAD_REQUEST)


class DetailRule(APIView):
    permission_classes = [IsAdmin]
    def get(self, request, pk):
        language = request.META.get("HTTP_ACCEPT_LANGUAGE")
        rule = retrieve_rule(pk, language)
        if rule:
            return Response(rule, status.HTTP_200_OK)
        else:
            return Response({'error': 'authorization error, check your email or password'}, status.HTTP_400_BAD_REQUEST)

class InValidIpsView(ModelViewSet):
    queryset = InValidIps.objects.all()
    permission_classes = [IsAdmin]
    serializer_class = IpSerializers
    def get_serializer(self, *args, **kwargs):
        if "data" in kwargs:
            data = kwargs["data"]
            if isinstance(data, list):
                kwargs["many"] = True
        return super().get_serializer(*args, **kwargs)
    
    def perform_update(self, serializer):
        super().perform_update(serializer)
        sync_db_and_snort()

    def perform_create(self, serializer):
        super().perform_create(serializer)
        sync_db_and_snort()

    def perform_destroy(self, instance):
        super().perform_destroy(instance)
        sync_db_and_snort()

class AssignOwner(APIView):
    permission_classes = [IsAdmin]    
    def post(self, request):
        language = request.META.get("HTTP_ACCEPT_LANGUAGE")
        requested_data = request.data
        try:
            serial = requested_data.get('serial')
            access_token = settings.SERVER_SIDE_ACCESS_TOKEN
            headers = {"Authorization" : f"Bearer {access_token}", "Accept-language": language}
            server_base_url = settings.IPS_CLIENT_SERVER_URL
            server_assign_owner_url = server_base_url + f"/products/assign_owner/"
            body = {'serial' : serial}
            request = requests.post(url=server_assign_owner_url, data=body, headers=headers)
            if request.status_code == 200:
                response = json.loads(request.content)
                set_device_serial(serial)
                return Response({"info":"serial assigend"}, status.HTTP_200_OK)
            elif request.status_code == 401:
                access_token = get_access_token_from_server()
                if access_token:
                    headers = {"Authorization" : f"Bearer {access_token}", "Accept-language": language}
                    request = requests.post(url=server_assign_owner_url, data=body, headers=headers)
                    if request.status_code == 200:
                        response = json.loads(request.content)
                        set_device_serial(serial)
                        return Response({"info":"serial assigend"}, status.HTTP_200_OK)
                    elif request.status_code == 400: 
                        response = json.loads(request.content)
                        return Response({"error": response}, status.HTTP_400_BAD_REQUEST)
            elif request.status_code == 400:
                response = json.loads(request.content)
                return Response({"error": response}, status.HTTP_400_BAD_REQUEST)
            elif request.status_code == 403:
                response = json.loads(request.content)
                return Response({"error": response}, status.HTTP_403_FORBIDDEN)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "Invalid serial"}, status.HTTP_400_BAD_REQUEST)

