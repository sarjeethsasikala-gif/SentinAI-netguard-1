# Backend Runtime
FROM python:3.9-slim

# Working Directory
WORKDIR /app
ENV PYTHONUNBUFFERED=1

# System Dependencies (if any specialized libs needed, e.g. gcc for numpy)
# numpy/pandas usually have wheels, so slim is often fine.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Code
COPY . .

# Expose Port
EXPOSE 8000

# Start Command
CMD ["uvicorn", "backend.api_gateway:app", "--host", "0.0.0.0", "--port", "8000"]
