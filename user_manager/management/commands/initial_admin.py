from django.core.management.base import BaseCommand
from utils.functions import create_admin


class Command(BaseCommand):
    help = "create admin user"

    def handle(self, *args, **kwargs):
        # create_admin()
        pass
