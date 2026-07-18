FROM python:3.12-slim

RUN useradd --create-home --shell /usr/sbin/nologin bridge
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py crypto.py ./

USER bridge

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
