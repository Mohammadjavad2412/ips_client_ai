.PHONY: initialize run initial_admin

initialize:
	python3 manage.py makemigrations
	python3 manage.py migrate

initial_admin:
	python3 manage.py initial_admin

run_celery:
	celery -A ips_client worker --loglevel=INFO

run_periodic_tasks:
	celery -A ips_client beat --loglevel=INFO --scheduler django_celery_beat.schedulers:DatabaseScheduler

run_uvicorn:
	python3 -m uvicorn ips_client.asgi:application --host 10.27.95.200 --port 8000

run:
	python3 manage.py run_app
