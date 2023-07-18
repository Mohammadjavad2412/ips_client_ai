.PHONY: initialize run initial_admin

initialize:
	python3 manage.py makemigrations
	python3 manage.py migrate

initial_admin:
	python3 manage.py initial_admin

run_uvicorn:
	python3 -m uvicorn ips_client.asgi:application --host 10.27.95.200 --port 8000

run:
	python3 manage.py run_app
