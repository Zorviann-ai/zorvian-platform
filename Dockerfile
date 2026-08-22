FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py app_gate5.py app_gate6.py app_gate7.py app_gate8.py app_gate9.py app_gate10.py email_branding.py ./
COPY intelligence ./intelligence
COPY deployment ./deployment
COPY beta ./beta
EXPOSE 8000
CMD ["sh","-c","uvicorn app_gate10:app --host 0.0.0.0 --port ${PORT:-8000}"]
