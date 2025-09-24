FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1     TIMEBOARD_TZ=UTC RELEASE_VERSION=dev REPOSITORY_URL=https://github.com/owner/repo

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app
EXPOSE 8000
VOLUME ["/data"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
