import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ips_client.settings")
app = Celery("ips_client")
app.config_from_object("django.conf:settings", namespace="IPS_CLIENT_PROXY_WALLET")
# Load task modules from all registered Django app configs.
app.autodiscover_tasks()
app.conf.beat_schedule = {
    "periodic_dnp3_packets": {
        "task": "rules.tasks.period_dnp3_packets",
        "schedule": crontab(minute="*/1"),
    },
}
