# VibeSec — portable container (works on Render, Railway, Fly.io, Cloud Run, etc.)
FROM python:3.12-slim

WORKDIR /app

# Install deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Bind to all interfaces inside the container; the host maps a public port.
# Most platforms inject $PORT automatically — server.py reads it.
ENV HOST=0.0.0.0
ENV PORT=8000
EXPOSE 8000

CMD ["python", "server.py"]
