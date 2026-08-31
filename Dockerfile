FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py app_gate5.py app_gate6.py app_gate7.py app_gate8.py app_gate9.py app_gate10.py app_gate11.py app_gate12.py provider_mesh.py email_branding.py control_plane.py ./
COPY migrations ./migrations
COPY intelligence ./intelligence
COPY deployment ./deployment
COPY beta ./beta
EXPOSE 8000
# Previous stable entrypoint: uvicorn app_gate11:app
CMD ["sh","-c","uvicorn app_gate12:app --host 0.0.0.0 --port ${PORT:-8000}"]
