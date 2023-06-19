from ips_client import settings
from ips_client.settings import (
    BASE_DIR,
    IPS_CLIENT_MODE,
    IPS_CLIENT_SNORT_RULES_PATH,
    IPS_CLIENT_PRODUCTION_CONTAINER_NAME,
    IPS_CLIENT_SNORT_CONF_PATH,
    IPS_CLIENT_SNORT2_SNORT_LUA_FILE,
    IPS_CLIENT_SNORT2_LUA_PATH,
    IPS_CLIENT_SNORT_LUA_FILE,
    IPS_CLIENT_SNORT_DEFAULT_LUA_FILE,
    IPS_CLIENT_LOG_SNORT_PATH,
    IPS_CLIENT_LOG_RABBIT_PATH
)
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
import signal

def get_rules_list(language="en-us"):
    server_base_url = settings.IPS_CLIENT_SERVER_URL
    server_rules_list_url = server_base_url + "/rules/list"
    try: 
        access_token = settings.SERVER_SIDE_ACCESS_TOKEN  
        headers = {"Authorization" : f"Bearer {access_token}","Accept-Language": language}
        request = requests.get(server_rules_list_url, headers=headers)
        if request.status_code == 200:
            rules_list = json.loads(request.content)
            return rules_list
        else:
            access_token = get_access_token_from_server()
            if access_token:
                headers = {"Authorization" : f"Bearer {access_token}", "Accept-Language": language}
                request = requests.get(server_rules_list_url, headers=headers)
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

def clean_rules_dir(path):
    # os.chdir(f"{IPS_CLIENT_SNORT_RULES_PATH}")
    COMMAND = ['sudo', 'rm', '-r', '*', path]
    proc = sp.Popen(COMMAND, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
    proc.communicate()

def create_rules_files():    
    clean_rules_dir(IPS_CLIENT_SNORT_RULES_PATH)
    rules = Rules.objects.all()
    for rule in rules:
        rule_name = rule.rule_name
        rule_code = rule.rule_code
        path = settings.IPS_CLIENT_SNORT_RULES_PATH + f"{rule_name}.rules"
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
    convert_snort_conf()
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
    admin_user = Users.objects.get(is_superuser=True, is_admin=True)
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

def replace_ips_in_snort_conf(snort_conf_path):
    ips = ValidIps.objects.all()
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
 
def create_lua_from_conf():
    os.chdir(f'{IPS_CLIENT_SNORT2_LUA_PATH}')
    COMMAND = ['snort2lua', '-c', f"{IPS_CLIENT_SNORT_CONF_PATH}"]
    proc = sp.Popen(COMMAND, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
    proc.communicate()

def cp_lua_file_to_desired_loc():
    COMMAND = ['sudo' ,'cp', '-f', f"{IPS_CLIENT_SNORT2_SNORT_LUA_FILE}", f"{IPS_CLIENT_SNORT_LUA_FILE}"]
    proc = sp.Popen(COMMAND, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
    proc.communicate()

def edit_snort_lua_file():
    change_mod(f"{IPS_CLIENT_SNORT2_LUA_PATH}/")
    change_mod(f"{IPS_CLIENT_SNORT2_SNORT_LUA_FILE}")
    with open(f"{IPS_CLIENT_SNORT2_SNORT_LUA_FILE}", "r") as snort_lua:
        snort_lua = snort_lua.read()
        edited_snort_lua = re.sub(r"dofile.*", f"dofile('{IPS_CLIENT_SNORT_DEFAULT_LUA_FILE}')", snort_lua, re.MULTILINE)
        with open(f"{IPS_CLIENT_SNORT2_SNORT_LUA_FILE}", 'w') as new_snort_lua:
            new_snort_lua.write(edited_snort_lua)

def convert_snort_conf():
    create_lua_from_conf()
    edit_snort_lua_file()
    cp_lua_file_to_desired_loc()

def restart_snort():
    if IPS_CLIENT_MODE == "development":
        try:
            change_mod(IPS_CLIENT_LOG_RABBIT_PATH)
            change_mod(IPS_CLIENT_LOG_SNORT_PATH)
            COMMAND = ['sudo','systemctl','restart', 'snort']
            proc = sp.Popen(COMMAND, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
            proc.communicate()
        except sp.CalledProcessError as e:
            logging.error({"Error": e})
    else:    
        sp.run(['sudo', 'lxc', 'exec', f"{IPS_CLIENT_PRODUCTION_CONTAINER_NAME}", "/bin/bash"])
