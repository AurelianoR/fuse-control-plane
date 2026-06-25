FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Default command is overridden per service in docker-compose / Azure.
CMD ["uvicorn", "fuse.main:app", "--host", "0.0.0.0", "--port", "8000"]
