from typing import Any, Optional
from django.core.management.base import BaseCommand
import subprocess
import threading
import logging
import traceback

class Command(BaseCommand):
    help = "run application with creating a super user"

    def initial(self):
        try:
            subprocess.run(["make", "initialize"])
            subprocess.run(["make", "initial_admin"])
        except:
            logging.error(traceback.format_exc())

    def run_uvicorn(self):
        subprocess.run(["make", "run_uvicorn"])

    def handle(self, *args, **kwargs):
        self.initial()
        self.run_uvicorn()
