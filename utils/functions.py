from ips_client import settings
from ips_client.settings import (
    BASE_DIR,
    IPS_CLIENT_MODE,
    IPS_CLIENT_SNORT_RULES_PATH,
    IPS_CLIENT_SNORT_CONF_PATH,
    IPS_CLIENT_SNORT2_SNORT_LUA_FILE,
    IPS_CLIENT_SNORT2_LUA_PATH,
    IPS_CLIENT_SNORT_LUA_FILE,
    IPS_CLIENT_SNORT_DEFAULT_LUA_FILE,
    IPS_CLIENT_LOG_SNORT_PATH,
    IPS_CLIENT_LOG_RABBIT_PATH,
    IPS_CLIENT_RESTART_SNORT_COMMAND,
    IPS_CLIENT_CREATE_LUA_FROM_CONF_COMMAND,
    IPS_CLIENT_CP_LUA_FILE_TO_DESIRED_LOC_COMMAND,
    IPS_CLIENT_ELASTIC_HOST,
    IPS_CLIENT_ELASTIC_PORT,
    IPS_CLIENT_KIBANA_HOST,
    IPS_CLIENT_KIBANA_PORT,
    IPS_CLIENT_ELK_USER_NAME,
    IPS_CLIENT_ELK_PASSWORD,
    IPS_CLIENT_NTOPNG_HOST,
    IPS_CLIENT_NTOPNG_PORT
)
from rules.models import Rules
from pathlib import Path
from ips_client import settings
from user_manager.models import Users
from user_manager.models import UserManagement
from rules.models import InValidIps
from elasticsearch import Elasticsearch
import requests
import json
import traceback
import logging
import os
import re
import subprocess as sp
import psutil
import subprocess

def get_rules_list(language="en-us", params=None):
    server_base_url = settings.IPS_CLIENT_SERVER_URL
    server_rules_list_url = server_base_url + "/rules/list"
    try: 
        access_token = settings.SERVER_SIDE_ACCESS_TOKEN  
        headers = {"Authorization" : f"Bearer {access_token}","Accept-Language": language}
        request = requests.get(server_rules_list_url, headers=headers, params=params)
        if request.status_code == 200:
            rules_list = json.loads(request.content)
            return rules_list
        else:
            access_token = get_access_token_from_server()
            if access_token:
                headers = {"Authorization" : f"Bearer {access_token}", "Accept-Language": language}
                request = requests.get(server_rules_list_url, headers=headers, params=params)
                rules_list = json.loads(request.content)
                return rules_list
            else:
                return None
    except:
        logging.error(traceback.format_exc())
        return None    

def retrieve_rule(pk, language="en-us"):
    server_base_url = settings.IPS_CLIENT_SERVER_URL
    server_retrieve_rule_url = server_base_url + f"/rules/retrieve/{pk}"
    try:
        access_token = settings.SERVER_SIDE_ACCESS_TOKEN  
        headers = {"Authorization" : f"Bearer {access_token}", "Accept-Language": language}
        request = requests.get(server_retrieve_rule_url, headers=headers)
        if request.status_code == 200:
            rule = json.loads(request.content)
            return rule
        else:
            if access_token:
                access_token = get_access_token_from_server()
                headers = {"Authorization" : f"Bearer {access_token}", "Accept-Language": language}
                request = requests.get(server_retrieve_rule_url, headers=headers)
                rule = json.loads(request.content)
                return rule
            else:
                return None
    except:
        logging.error(traceback.format_exc())
        return None
 
def change_mod(path):
    COMMAND = ['sudo','chmod','777',path]
    proc = sp.Popen(COMMAND, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
    proc.communicate()

def del_rule_dir():
    try:
        for file in os.scandir(f"{IPS_CLIENT_SNORT_RULES_PATH}/"):
            os.remove(file.path)
    except:
        logging.error(traceback.format_exc())

def create_rules_files():
    del_rule_dir()
    rules = Rules.objects.all()
    for rule in rules:
        rule_name = rule.rule_name
        rule_code = rule.rule_code
        path = settings.IPS_CLIENT_SNORT_RULES_PATH + f"/{rule_name}.rules"
        dir_path = settings.IPS_CLIENT_SNORT_RULES_PATH
        change_mod(dir_path)
        change_mod(path)
        with open(path, 'w+') as my_rule:
            my_rule.write(rule_code)

def generate_snort_conf():
    raw_path = os.path.join(BASE_DIR,"raw_snort.conf")
    snort_conf_path = os.path.join(BASE_DIR,"snort.conf")
    #first includ the rules in snort_conf, then change ipvars with replace_ips_in_snort_conf method.
    try:
        with open(raw_path, 'r') as raw_snort:
            raw = raw_snort.read()
            rules = create_include_rule_snort()
            raw = raw + rules
            with open(snort_conf_path,"w+") as snort_conf:
                snort_conf.write(raw)
        replace_ips_in_snort_conf(snort_conf_path)
    except:
        logging.error(traceback.format_exc())

def create_include_rule_snort():
    text = ""
    rules = Rules.objects.all()
    for rule in rules:
        rule_name = rule.rule_name
        text = text+ f"include $RULE_PATH/{rule_name}.rules \n"
    return text

def set_snort_conf():
    snort_conf_path = settings.IPS_CLIENT_SNORT_CONF_PATH
    snort_conf_path_path = Path(snort_conf_path)
    snort_conf_dir_path = snort_conf_path_path.parent.absolute()
    local_snort_conf_path = os.path.join(BASE_DIR, "snort.conf")
    change_mod(snort_conf_path)
    change_mod(snort_conf_dir_path)
    generate_snort_conf()
    with open(local_snort_conf_path, 'r') as local_snort_conf:
        local_conf = local_snort_conf.read()
        with open(snort_conf_path, 'w+') as snort_conf:
            snort_conf.write(local_conf)

def sync_db_and_snort():
    create_rules_files()
    set_snort_conf()
    restart_snort()

def delete_rule_file(rule_name):
    snort_rules_path = settings.IPS_CLIENT_SNORT_RULES_PATH
    change_mod(snort_rules_path)
    os.remove(snort_rules_path+f"{rule_name}.rules")

def get_access_token_from_server():
    body = {
        "email": settings.SERVER_SIDE_EMAIL ,
        "password": settings.SERVER_SIDE_PASSWORD
    }
    server_authentication_url = settings.IPS_CLIENT_SERVER_URL + "/users/token/"
    request = requests.post(url=server_authentication_url,data=body)
    response = json.loads(request.content)
    if request.status_code == 200:
        access_token = response['access']
        raw_path = os.path.join(BASE_DIR,"ips_client","settings.py")
        with open(raw_path, "r") as settings_file:
            settings_file = settings_file.read()
            new_conf = re.sub(r"SERVER_SIDE_ACCESS_TOKEN.*", f"SERVER_SIDE_ACCESS_TOKEN='{str(access_token)}'", settings_file, re.MULTILINE)
        with open(raw_path, 'w') as new_settings_file:
            new_settings_file.write(new_conf)
        return access_token
    else:
        return None 
    
def create_admin():
    try:
        admin_user = Users.objects.filter(is_superuser=True).exists()
        if admin_user:
            pass
        else:
            Users.objects.create_superuser(email="admin@admin.com", password="Admin@11")
    except:
        logging.error(traceback.format_exc())
        

def set_device_serial(serial):
    raw_path = os.path.join(BASE_DIR,"ips_client","settings.py")
    with open(raw_path, "r") as settings_file:
        settings_file = settings_file.read()
        new_conf = re.sub(r"DEVICE_SERIAL.*", f"DEVICE_SERIAL='{str(serial)}'", settings_file, re.MULTILINE)
    with open(raw_path, 'w') as new_settings_file:
        new_settings_file.write(new_conf)

def replace_ips_in_snort_conf(snort_conf_path):
    ips = InValidIps.objects.all()
    internal_ips = [ip.ip for ip in ips if ip.ip_type == "Internal"]
    internal_ips = str(internal_ips).replace(' ', '')
    external_ips = [ip.ip for ip in ips if ip.ip_type == "External"]
    external_ips = str(external_ips).replace(' ', '')
    if internal_ips == "[]":
        internal_ips = "any"
    if external_ips == "[]":
        external_ips = "any"
    with open(snort_conf_path, 'r') as snort_conf:
        snort_conf = snort_conf.read()
        new_conf = re.sub(r"ipvar HOME_NET.*", f"ipvar HOME_NET {internal_ips}", snort_conf, re.MULTILINE)
        with open(snort_conf_path, 'w') as snort_conf_w:
            snort_conf_w.write(new_conf)
    with open(snort_conf_path, 'r') as snort_conf:
        snort_conf = snort_conf.read()
        new_conf = re.sub(r"ipvar EXTERNAL_NET.*", f"ipvar EXTERNAL_NET {external_ips}", snort_conf, re.MULTILINE)
        with open(snort_conf_path, 'w') as snort_conf_w:
            snort_conf_w.write(new_conf)
    with open(snort_conf_path, 'r') as snort_conf:
        snort_conf = snort_conf.read()
        new_conf = snort_conf.replace("'", "")
        with open(snort_conf_path, 'w') as snort_conf_w:
            snort_conf_w.write(new_conf)

def restart_snort():
    try:
        change_mod(IPS_CLIENT_LOG_RABBIT_PATH)
        change_mod(IPS_CLIENT_LOG_SNORT_PATH)
        re_sn_co = IPS_CLIENT_RESTART_SNORT_COMMAND
        restart_snort_command = [str(word) for word in re_sn_co.split()]
        COMMAND = restart_snort_command
        # COMMAND = ['sudo','systemctl','restart', 'snort']
        proc = sp.Popen(COMMAND, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
        proc.communicate()
    except sp.CalledProcessError as e:
        logging.error({"Error": e})

def check_snort_health():
    snort_running = False
    for proc in psutil.process_iter():
        try:
            if 'snort' in proc.name().lower():
                snort_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if snort_running:
        return True
    else:
        return False

def check_elastic_health():
    try:
        es = Elasticsearch(hosts=f"http://{IPS_CLIENT_ELASTIC_HOST}:{IPS_CLIENT_ELASTIC_PORT}" ,http_auth=(f"{IPS_CLIENT_ELK_USER_NAME}", f"{IPS_CLIENT_ELK_PASSWORD}"))
        ping_exist = es.ping()
        if ping_exist:
            return True
        else:
            return False
    except:
        logging.error(traceback.format_exc())

def check_kibana_health():
    kibana_url = f"http://{IPS_CLIENT_KIBANA_HOST}:{IPS_CLIENT_KIBANA_PORT}/api/status"
    # kibana_url = "http://localhost:5601/api/status"
    try:
        response = requests.get(kibana_url, auth=(f"{IPS_CLIENT_ELK_USER_NAME}", f"{IPS_CLIENT_ELK_PASSWORD}"))
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        logging.error(traceback.format_exc())
        logging.info("unable to connect to kibana")
        return False

def check_zeek_health():
    zeek_running = False
    for proc in psutil.process_iter():
        try:
            if 'zeek' in proc.name().lower():
                zeek_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if zeek_running:
        return True
    else:
        return False

def check_filebeat_health():
    filebeat_running = False
    for proc in psutil.process_iter():
        try:
            if 'filebeat' in proc.name().lower():
                filebeat_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if filebeat_running:
        return True
    else:
        return False

def check_ntopng_health():
    try:
        ntop_ng_url = f"http://{IPS_CLIENT_NTOPNG_HOST}:{IPS_CLIENT_NTOPNG_PORT}"
        request = requests.get(url=ntop_ng_url)
        if request.status_code == 302:
            return True
        else:
            return False
    except:
        logging.error(traceback.format_exc())
        return False
    # ntopng_running = False
    # for proc in psutil.process_iter():
    #     try:
    #         if 'ntopng' in proc.name().lower():
    #             ntopng_running = True
    #             break
    #     except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
    #         pass
    # if ntopng_running:
    #     return True
    # else:
    #     return False

def is_equal_code(front_code, server_code):
        reg_pattern = r"(alert|drop|block|reject|pass)[\s\S]*?;\)"
        matches = re.finditer(reg_pattern, front_code, re.MULTILINE)
        recieved_rule_list = []
        server_code_regex_applied = []
        for match in matches:
            recieved_rule_list.append(match.group(0))
        matches = re.finditer(reg_pattern, server_code, re.MULTILINE)
        for match in matches:
            server_code_regex_applied.append(match.group(0))
        # without_action_policy_reg_pattern = r"(?i)^(drop|alert|block|pass|reject)\s+(.+)$"
        without_action_policy_reg_pattern = r'^(drop|alert|block|pass|reject)\s*(.*)'
        server_code_without_action = []
        for server_policy in server_code_regex_applied:
            server_policy_without_action_code = re.match(without_action_policy_reg_pattern, server_policy)
            action = server_policy_without_action_code.group(1)
            rest_of_the_code = server_policy_without_action_code.group(2)
            server_code_without_action.append(rest_of_the_code)
        front_code_without_action = []
        for policy in recieved_rule_list:
            policy_without_action_code = re.match(without_action_policy_reg_pattern, policy)
            action = policy_without_action_code.group(1)
            rest_of_the_code = policy_without_action_code.group(2)
            front_code_without_action.append(rest_of_the_code)
        try:
            for i in range(len(server_code_without_action)):
                if server_code_without_action[i] in front_code_without_action:
                    check = 'ok'
                else:
                    return False
            return True
        except:
            return False
                    
def protocol_mapper(protocol):
    if protocol == "dnp3":
        from Ai.clients.dnp3 import Dnp3Client

        return Dnp3Client()
    if protocol == "modbus":
        from Ai.clients.modbus import ModBusClient

        return ModBusClient()
    else:
        raise NotImplementedError
    


