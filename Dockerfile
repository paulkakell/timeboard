FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY settings.sample.yml /app/settings.sample.yml
COPY README.md /app/README.md

# Default locations (override via env)
ENV TIMEBOARD_SETTINGS=/data/settings.yml

EXPOSE 8888

CMD ["python", "-m", "app.run"]
