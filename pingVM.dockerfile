FROM python:3

## Installing dependencies
RUN apt-get update && apt-get install -y iputils-ping

WORKDIR /app/

COPY logs-collector.py /app/

CMD ["python", "logs-collector.py"]
