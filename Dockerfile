FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py app_gate5.py ./
COPY intelligence ./intelligence
EXPOSE 8000
CMD ["sh","-c","uvicorn app_gate5:app --host 0.0.0.0 --port ${PORT:-8000}"]
