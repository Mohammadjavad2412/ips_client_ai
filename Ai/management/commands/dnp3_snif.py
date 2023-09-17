from typing import Any, Optional
from django.core.management.base import BaseCommand
from Ai.clients.dnp3 import Dnp3Client


class Command(BaseCommand):
    help = "dnp3 capture packet"

    def handle(self, *args, **kwargs):
        dnp3_client = Dnp3Client()
        dnp3_client.start_sniffing()