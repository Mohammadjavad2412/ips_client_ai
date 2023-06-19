FROM nexus:443/ubuntu:20.04

USER root
COPY . ./app
WORKDIR /app
RUN echo 'deb http://10.27.95.5:8081/repository/apt-proxy/ubuntu jammy-updates main restricted universe' > /etc/apt/sources.list && echo 'deb http://10.27.95.5:8081/repository/apt-proxy/ubuntu jammy main restricted universe' >> /etc/apt/sources.list && apt-get update && apt-get install -y python3 python3-pip && pip install --index-url http://10.27.95.5:8081/repository/pypi-all/simple --trusted-host 10.27.95.5 -r requirements.txt
EXPOSE 8000
