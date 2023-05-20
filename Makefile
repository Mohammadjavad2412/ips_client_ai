.PHONY: initialize run initial_admin

initialize:
	python3 manage.py makemigrations
	python3 manage.py migrate

initial_admin:
	python3 manage.py initial_admin

run_uvicorn:
	uvicorn ips_client.asgi:application --host 0.0.0.0 --port 8000

run:
	python3 manage.py run_app