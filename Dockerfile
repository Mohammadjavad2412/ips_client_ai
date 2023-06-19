FROM nexus:443/ubuntu:20.04

USER root
COPY . ./app
WORKDIR /app
RUN echo 'deb http://10.27.95.5:8081/repository/apt-proxy/ubuntu jammy-updates main restricted universe' > /etc/apt/sources.list && echo 'deb http://10.27.95.5:8081/repository/apt-proxy/ubuntu jammy main restricted universe' >> /etc/apt/sources.list && apt-get update && apt-get install python3 python3-pip && pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
