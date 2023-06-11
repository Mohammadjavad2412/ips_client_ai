from ips_client import settings
from ips_client.settings import BASE_DIR
from rules.models import Rules
from pathlib import Path
from ips_client import settings
from user_manager.models import Users
from user_manager.models import UserManagement
from rules.models import ValidIps
import requests
import json
import traceback
import logging
import os
import re
import subprocess as sp

def get_rules_list():
    server_base_url = settings.IPS_CLIENT_SERVER_URL
    server_rules_list_url = server_base_url + "/rules/list"  
    try: 
        access_token = settings.SERVER_SIDE_ACCESS_TOKEN  
        headers = {"Authorization" : f"Bearer {access_token}"}
        request = requests.get(server_rules_list_url, headers=headers)
        if request.status_code == 200:
            rules_list = json.loads(request.content)
            return rules_list
        else:
            access_token = get_access_token_from_server()
            if access_token:
                headers = {"Authorization" : f"Bearer {access_token}"}
                request = requests.get(server_rules_list_url, headers=headers)
                rules_list = json.loads(request.content)
                return rules_list
            else:
                return None
    except:
        logging.error(traceback.format_exc())
        return None    

def retrieve_rule(pk):
    server_base_url = settings.IPS_CLIENT_SERVER_URL
    server_retrieve_rule_url = server_base_url + f"/rules/retrieve/{pk}/"
    try:
        access_token = settings.SERVER_SIDE_ACCESS_TOKEN  
        headers = {"Authorization" : f"Bearer {access_token}"}
        request = requests.get(server_retrieve_rule_url, headers=headers)
        if request.status_code == 200:
            rule = json.loads(request.content)
            return rule
        else:
            if access_token:
                access_token = get_access_token_from_server()
                headers = {"Authorization" : f"Bearer {access_token}"}
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

def generate_snort_conf():
    raw_path = os.path.join(BASE_DIR,"raw_snort.conf")
    snort_conf_path = os.path.join(BASE_DIR,"snort.conf")
    try:
        with open(raw_path, 'r') as raw_snort:
            raw = raw_snort.read()
            rules = create_include_rule_snort()
            raw = raw + rules
            with open(snort_conf_path,"w+") as snort_conf:
                snort_conf.write(raw)
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
    snort_conf_path = settings.SNORT_CONF_PATH
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

def delete_rule_file(rule_name):
    snort_rules_path = settings.IPS_CLIENT_SNORT_RULES_PATH
    change_mod(snort_rules_path)
    os.remove(snort_rules_path+f"{rule_name}.rules")

def set_home_net_ipvar(ip_list, ip_type):
    local_raw_snort_conf_path = os.path.join(BASE_DIR, "raw_snort.conf")
    local_snort_conf_path = os.path.join(BASE_DIR, "snort.conf")
    snort_conf_path = settings.IPS_CLIENT_SNORT_CONF_PATH
    snort_conf_path_path = Path(snort_conf_path)
    snort_conf_dir_path = snort_conf_path_path.parent.absolute()
    change_mod(snort_conf_path)
    change_mod(snort_conf_dir_path)
    if ip_type == 'Internal':
        with open(snort_conf_path, 'r') as snort_conf:
            snort_conf = snort_conf.read()
            new_conf = re.sub(r"ipvar HOME_NET.*", f"ipvar HOME_NET {ip_list}", snort_conf, re.MULTILINE)
            with open(snort_conf_path, 'w') as snort_conf_w:
                snort_conf_w.write(new_conf)
    if ip_type == 'External':
        with open(snort_conf_path, 'r') as snort_conf:
            snort_conf = snort_conf.read()
            new_conf = re.sub(r"ipvar EXTERNAL_NET.*", f"ipvar EXTERNAL_NET {ip_list}", snort_conf, re.MULTILINE)
            with open(snort_conf_path, 'w') as snort_conf_w:
                snort_conf_w.write(new_conf)

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
    admin_user = Users.objects.get(is_superuser=True)
    if admin_user:
        pass
    else:
        UserManagement.create_superuser(email="admin@admin.com", password="admin")

def set_device_serial(serial):
    raw_path = os.path.join(BASE_DIR,"ips_client","settings.py")
    with open(raw_path, "r") as settings_file:
        settings_file = settings_file.read()
        new_conf = re.sub(r"DEVICE_SERIAL.*", f"DEVICE_SERIAL='{str(serial)}'", settings_file, re.MULTILINE)
    with open(raw_path, 'w') as new_settings_file:
        new_settings_file.write(new_conf)

def sync_db_snort_ips():
    local_raw_snort_conf_path = os.path.join(BASE_DIR, "raw_snort.conf")
    local_snort_conf_path = os.path.join(BASE_DIR, "snort.conf")
    snort_conf_path = settings.IPS_CLIENT_SNORT_CONF_PATH
    snort_conf_path_path = Path(snort_conf_path)
    snort_conf_dir_path = snort_conf_path_path.parent.absolute()
    change_mod(snort_conf_path)
    change_mod(snort_conf_dir_path)
    ips = ValidIps.objects.all()
    internal_ips = [ip.ip for ip in ips if ip.ip_type == "Internal"]
    external_ips = [ip.ip for ip in ips if ip.ip_type == "External"]
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
