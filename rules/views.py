from .models import Rules
from .serializers import RulesSerializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Rules
from utils.functions import get_rules_list, retrieve_rule, change_mod,set_snort_conf, delete_rule_file, set_home_net_ipvar
from ips_client import settings
import logging
import traceback

# Create your views here.


class RulesList(APIView):
    """
    get list of rules or filtered rules by action.
    """

    def get(self, request):
        rules_list = get_rules_list()
        if rules_list:
            return Response(rules_list, status.HTTP_200_OK)
        else:
            return Response({'error': 'authorization error, check your email or password'}, status.HTTP_400_BAD_REQUEST)

class EnableRule(APIView):
    """
    enable a specific rule.
    """        
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
    def get(self,request):
        rules = Rules.objects.all()
        serialized_rules = RulesSerializers(rules, many=True)
        return Response(serialized_rules.data, status.HTTP_200_OK)

class DetailRule(APIView):
    def get(self, request, pk):
        rule = retrieve_rule(pk)
        if rule:
            return Response(rule, status.HTTP_200_OK)
        else:
            return Response({'error': 'authorization error, check your email or password'}, status.HTTP_400_BAD_REQUEST)
        
class SetHomeNet(APIView):
    def post(self, request):
        requested_data = request.data
        try:
            ip_list = requested_data.get('ip_list')
            set_home_net_ipvar(ip_list)
            return Response("ipvar changed successfully", status.HTTP_200_OK)
        except: 
            logging.error(traceback.format_exc())
            return Response({"error": "ip list field is invalid"}, status.HTTP_400_BAD_REQUEST)
