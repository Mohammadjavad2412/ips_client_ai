from utils.functions import (
    check_snort_health,
    check_elastic_health,
    check_kibana_health,
    check_zeek_health,
    check_filebeat_health,
    check_ntopng_health
)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class HealthCheck(APIView):
    def get(self, request):
        snort_status = check_snort_health()
        elk_status = check_elastic_health()
        kibana_status = check_kibana_health()
        zeek_status = check_zeek_health()
        filebeat_status = check_filebeat_health()
        ntopng_status = check_ntopng_health()
        return Response({"ips": snort_status, "monitoringEngine": elk_status, "monitoringUi": kibana_status, "ids": zeek_status, "shippingLogs": filebeat_status, "trafficMonitoring": ntopng_status}, status.HTTP_200_OK)
    