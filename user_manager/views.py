from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from user_manager.permissions import IsAdmin
from user_manager.models import Users
from user_manager.serializers import UserSerializer
from ips_client.settings import IPS_CLIENT_SERVER_URL, SERVER_SIDE_EMAIL, SERVER_SIDE_PASSWORD, SERVER_SIDE_ACCESS_TOKEN
from ips_client import settings
from rest_framework.response import Response
from rest_framework import status
from ips_client.settings import BASE_DIR
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
    permission_classes = [IsAdmin]

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
                    raw_path = os.path.join(BASE_DIR,"settings.py")
                    with open(raw_path, "r") as settings_file:
                        settings_file = settings_file.read()
                        new_conf = re.sub(r"SERVER_SIDE_EMAIL.*", f"SERVER_SIDE_EMAIL='{str(email)}'", settings_file, re.MULTILINE)
                        new_conf = re.sub(r"SERVER_SIDE_PASSWORD.*", f"SERVER_SIDE_PASSWORD='{str(password)}'", new_conf, re.MULTILINE)
                        new_conf = re.sub(r"SERVER_SIDE_ACCESS_TOKEN.*", f"SERVER_SIDE_ACCESS_TOKEN='{str(access_token)}'", new_conf, re.MULTILINE)
                    with open(raw_path, 'w') as new_settings_file:
                        new_settings_file.write(new_conf)
                    return Response("successfully authorized", status.HTTP_200_OK)
                elif request.status_code == 401:
                    return Response({"error": "Invalid email or password"}, status.HTTP_401_UNAUTHORIZED)

                else:
                    return Response({"error" : "server down, try later"}, status.HTTP_500_INTERNAL_SERVER_ERROR)            
            except:
                logging.error(traceback.format_exc())
                return Response({"error": "server down, try later"})
        else:
            return Response({"error": "email and password should be sent"}, status.HTTP_400_BAD_REQUEST)



