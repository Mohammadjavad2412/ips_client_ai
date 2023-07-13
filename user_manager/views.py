from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from user_manager.permissions import IsAdmin, IsSuperUser, UserPermission
from rest_framework.permissions import IsAuthenticated
from user_manager.models import Users
from user_manager.serializers import UserSerializer, LoginSerializer
from ips_client.settings import IPS_CLIENT_SERVER_URL
from rest_framework.response import Response
from rest_framework import status
from ips_client.settings import BASE_DIR
from django.contrib.auth import logout, login
from rest_framework.authentication import BasicAuthentication
from ips_client import settings
from rest_framework_simplejwt.tokens import RefreshToken
from utils.functions import get_access_token_from_server
import os
import logging
import traceback
import requests
import json
import re

# Create your views here.

class UserView(ModelViewSet):
    queryset = Users.objects.all()
    serializer_class = UserSerializer
    permission_classes = [UserPermission]


class LoginView(APIView):
    
    def post(self, request):
        requested_data = request.data
        ser_data = LoginSerializer(data=requested_data)
        if ser_data.is_valid():
            email = requested_data.get("email") 
            password = requested_data.get("password")
            try:
                user = Users.objects.get(email=email)
                if user.check_password(password):
                    ser_user = UserSerializer(user)
                    token = RefreshToken.for_user(user)
                    access_token = str(token.access_token)
                    refresh_token = str(token)
                    login(request, user)
                    server_side_email = settings.SERVER_SIDE_EMAIL
                    server_side_password = settings.SERVER_SIDE_PASSWORD
                    ips_authentication_server_url = IPS_CLIENT_SERVER_URL + "/users/token/"
                    body = {
                        "email" : server_side_email,
                        "password" : server_side_password
                    }
                    try:
                        request = requests.post(url = ips_authentication_server_url, data=body)
                    except:
                        response = {}
                        response = ser_user.data
                        response['is_authenticated'] = True
                        response['access_token'] = access_token
                        response['refresh_token'] = refresh_token
                        return Response(response, status.HTTP_200_OK)    
                    if request.status_code == 200:
                        response ={}
                        response = ser_user.data
                        response['is_authenticated'] = True
                        response['access_token'] = access_token
                        response['refresh_token'] = refresh_token
                    else:
                        response ={}
                        response = ser_user.data
                        response['is_authenticated'] = False
                        response['access_token'] = access_token
                        response['refresh_token'] = refresh_token
                    return Response(response, status.HTTP_200_OK)
                else:
                    return Response({"error": "Invalid username or password"}, status.HTTP_400_BAD_REQUEST)
            except:
                logging.error(traceback.format_exc())
                return Response({"error": "user not found, signup first!"}, status.HTTP_400_BAD_REQUEST)
        else:
            return Response(ser_data.errors, status.HTTP_400_BAD_REQUEST)


class LogOutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [BasicAuthentication]
    def get(self, request):
        logout(request)
        return Response({"info":"logged out successfully"}, status.HTTP_200_OK)


class ServerAuthentication(APIView):

    permission_classes = [IsAdmin]
    
    def post(self, request):
        requested_data = request.data
        email = requested_data.get("email")
        password = requested_data.get("password")
        if email and password:
            ips_server_url = IPS_CLIENT_SERVER_URL + "/users/token/"
            body = {
                "email" : email,
                "password" : password
            }
            try:        
                request = requests.post(url=ips_server_url, data=body)
                if request.status_code == 200:
                    response = json.loads(request.content)
                    access_token = response['access']
                    raw_path = os.path.join(BASE_DIR,"ips_client","settings.py")
                    with open(raw_path, "r") as settings_file:
                        settings_file = settings_file.read()
                        new_conf = re.sub(r"SERVER_SIDE_EMAIL.*", f"SERVER_SIDE_EMAIL='{str(email)}'", settings_file, re.MULTILINE)
                        new_conf = re.sub(r"SERVER_SIDE_PASSWORD.*", f"SERVER_SIDE_PASSWORD='{str(password)}'", new_conf, re.MULTILINE)
                        new_conf = re.sub(r"SERVER_SIDE_ACCESS_TOKEN.*", f"SERVER_SIDE_ACCESS_TOKEN='{str(access_token)}'", new_conf, re.MULTILINE)
                    with open(raw_path, 'w') as new_settings_file:
                        new_settings_file.write(new_conf)
                    return Response({"info": "successfully authorized"}, status.HTTP_200_OK)
                elif request.status_code == 401:
                    return Response({"error": "Invalid email or password"}, status.HTTP_406_NOT_ACCEPTABLE)
                elif request.status_code == 400:
                    return Response({"error": "invalid data"}, status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"error" : "server down, try later"}, status.HTTP_500_INTERNAL_SERVER_ERROR)            
            except:
                logging.error(traceback.format_exc())
                return Response({"error": "server down, try later"})
        else:
            return Response({"error": "email and password should be sent"}, status.HTTP_400_BAD_REQUEST)


class ProductView(APIView):
    permission_classes = [IsAdmin|IsSuperUser]

    def get(self, request):
        ips_server_url = IPS_CLIENT_SERVER_URL
        ips_server_products_url = ips_server_url + f"/products/serial/{settings.DEVICE_SERIAL}"
        try:
            access_token = settings.SERVER_SIDE_ACCESS_TOKEN
            headers = {"Authorization" : f"Bearer {access_token}"}
            server_request = requests.get(url=ips_server_products_url, headers=headers)
            if server_request.status_code == 200:
                if request.user.is_superuser:                    
                    response = json.loads(server_request.content)
                else:
                    response = json.loads(server_request.content)
                    del response["owner"]
                    del response["creator"]
                return Response(response, status.HTTP_200_OK)
            if server_request.status_code == 401:
                access_token = get_access_token_from_server()
                if access_token:
                    headers = {"Authorization" : f"Bearer {access_token}"}
                    server_request = requests.get(url=ips_server_products_url, headers=headers)
                    if server_request.status_code == 200:
                        if request.user.is_superuser:                    
                            response = json.loads(server_request.content)
                        else:
                            response = json.loads(server_request.content)
                            del response["owner"]
                            del response["creator"]
                        return Response(response, status.HTTP_200_OK)
                    else:
                        return Response({"error":"something's wrong"}, status.HTTP_400_BAD_REQUEST)
            if str(server_request.status_code).startswith("4"):
                return Response({"error": " maybe wrong device id"}, status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"server down, try later"}, status.HTTP_500_INTERNAL_SERVER_ERROR)
        except:
            return Response({"error":"internal server error"}, status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProfileView(APIView):
    
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            ser_user = UserSerializer(user)
            response = {}
            response = ser_user.data
            server_side_email = settings.SERVER_SIDE_EMAIL
            server_side_password = settings.SERVER_SIDE_PASSWORD
            ips_authentication_server_url = IPS_CLIENT_SERVER_URL + "/users/token/"
            body = {
                "email" : server_side_email,
                "password" : server_side_password
            }
            try:
                request = requests.post(url = ips_authentication_server_url, data=body)
            except:
                response = {}
                response = ser_user.data
                response["is_authenticated"] = True
                return Response(response, status.HTTP_200_OK)
            if request.status_code == 200:
                response ={}
                response = ser_user.data
                response['is_authenticated'] = True
            else:
                response ={}
                response = ser_user.data
                response['is_authenticated'] = False
            return Response(response, status.HTTP_200_OK)
        except:
            return Response({"error": "no such a user, user not found!"}, status.HTTP_400_BAD_REQUEST)
