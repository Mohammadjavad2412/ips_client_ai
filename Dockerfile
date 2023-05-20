FROM python:3.8

USER root
COPY . ./app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
RUN python3 -m pip install -U pip
