from ips_client.celery import app
from utils.functions import dnp3_packet


@app.task
def periodic_dnp3_packets():
    dnp3_packet()