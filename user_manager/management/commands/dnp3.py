from django.core.management.base import BaseCommand
from utils.functions import dnp3_packet


class Command(BaseCommand):
    help = "dnp3 send packet"

    def handle(self, *args, **kwargs):
        dnp3_packet()
