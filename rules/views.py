from .models import Rules, ValidIps
from user_manager.models import Users
from .serializers import RulesSerializers, IpSerializers
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status
from .models import Rules
from ips_client.settings import BASE_DIR
from utils.functions import get_rules_list, retrieve_rule, change_mod,set_snort_conf, delete_rule_file, get_access_token_from_server,set_device_serial, sync_db_snort_ips
from ips_client import settings
from user_manager.permissions import IsAdmin
import logging
import traceback
import requests
import json
import ipaddress

# Create your views here.


class RulesList(APIView):
    """
    get list of rules or filtered rules by action.
    """
    permission_classes = [IsAdmin]
    def get(self, request):
        rules_list = get_rules_list()
        if rules_list:
            return Response(rules_list, status.HTTP_200_OK)
        if rules_list == []:
            return Response({"info": "currently there is no rules available"}, status.HTTP_200_OK)
        else:
            return Response({'error': 'you have not been authorized in server side'}, status.HTTP_407_PROXY_AUTHENTICATION_REQUIRED)

class EnableRule(APIView):
    """
    enable a specific rule.
    """        
    permission_classes = [IsAdmin]
    def post(self, request):
        requested_data = request.data
        try:
            rule_code = requested_data.get("rule_code")
            rule_name = requested_data.get("rule_name")
            rule_id = requested_data.get("rule_id")
        except:
            return Response({"error": "rule's code, rule's name or rule's is field is invalid"}, status.HTTP_400_BAD_REQUEST)
        path = settings.IPS_CLIENT_SNORT_RULES_PATH + f"{rule_name}.rules"
        dir_path = settings.IPS_CLIENT_SNORT_RULES_PATH
        change_mod(dir_path)
        change_mod(path)
        with open(path, 'w+') as my_rule:
            my_rule.write(rule_code)
        obj = Rules(id = rule_id, rule_name=rule_name)
        try:
            obj.save(force_insert=True)
            set_snort_conf()
            return Response({"info" : "rule submitted"}, status.HTTP_201_CREATED)
        except:
            logging.error(traceback.format_exc())

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
            return Response({"info": "rule deleted successfully"}, status.HTTP_200_OK)
        except:
            return Response({"error": "invalid name"}, status.HTTP_400_BAD_REQUEST)

class MyRules(APIView):
    # permission_classes = [IsAdmin]
    def get(self,request):
        rules = Rules.objects.all()
        serialized_rules = RulesSerializers(rules, many=True)
        return Response(serialized_rules.data, status.HTTP_200_OK)

class DetailRule(APIView):
    permission_classes = [IsAdmin]
    def get(self, request, pk):
        rule = retrieve_rule(pk)
        if rule:
            return Response(rule, status.HTTP_200_OK)
        else:
            return Response({'error': 'authorization error, check your email or password'}, status.HTTP_400_BAD_REQUEST)
        
class ValidIpsView(ModelViewSet):
    queryset = ValidIps.objects.all()
    # permission_classes = [IsAdmin]
    serializer_class = IpSerializers
    def get_serializer(self, *args, **kwargs):
        if "data" in kwargs:
            data = kwargs["data"]
            if isinstance(data, list):
                kwargs["many"] = True
        return super().get_serializer(*args, **kwargs)

class AssignOwner(APIView):
    permission_classes = [IsAdmin]    
    def post(self, request):
        requested_data = request.data
        try:
            serial = requested_data.get('serial')
            access_token = settings.SERVER_SIDE_ACCESS_TOKEN
            headers = {"Authorization" : f"Bearer {access_token}"}
            server_base_url = settings.IPS_CLIENT_SERVER_URL
            server_assign_owner_url = server_base_url + f"/products/assign_owner/"
            body = {'serial' : serial}
            request = requests.post(url=server_assign_owner_url, data=body, headers=headers)
            if request.status_code == 200:
                response = json.loads(request.content)
                set_device_serial(serial)
                users = Users.objects.all()
                for user in users:
                    user.device_serial = serial
                    user.save()
                return Response({"info":"serial assigend"}, status.HTTP_200_OK)
            elif request.status_code == 401:
                access_token = get_access_token_from_server()
                if access_token:
                    headers = {"Authorization" : f"Bearer {access_token}"}
                    request = requests.post(url=server_assign_owner_url, data=body, headers=headers)
                    if request.status_code == 200:
                        response = json.loads(request.content)
                        set_device_serial(serial)
                        for user in users:
                            user.device_serial = serial
                            user.save()
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

class DeviceInfo(APIView):
    permission_classes = [IsAdmin]
    def get(self, request):
        serial = settings.DEVICE_SERIAL
        server_base_url = settings.IPS_CLIENT_SERVER_URL
        server_device_info_url = server_base_url + f"/products/serial/{serial}"
        try:
            access_token = settings.SERVER_SIDE_ACCESS_TOKEN
            headers = {"Authorization" : f"Bearer {access_token}"}
            request = requests.get(url=server_device_info_url, headers=headers)
            if request.status_code == 200:
                response = json.loads(request.content)
                return Response(response, status.HTTP_200_OK)
            elif request.status_code == 401:
                access_token = get_access_token_from_server()
                if access_token:
                    headers = {"Authorization" : f"Bearer {access_token}"}
                    request = requests.get(url=server_device_info_url, headers=headers)
                    response = json.loads(request.content)
                    return Response(response, status.HTTP_200_OK)
            elif request.status_code == 403:
                return Response({"error": "Authorization required"}, status.HTTP_403_FORBIDDEN)
            else:
                return Response({"error": "server error, try later"}, status.HTTP_500_INTERNAL_SERVER_ERROR)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "server error, try later"}, status.HTTP_500_INTERNAL_SERVER_ERROR)
