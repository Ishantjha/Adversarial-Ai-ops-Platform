# Dockerfile
# Containerizes the entire AIOps Platform

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Create required directories
RUN mkdir -p data/raw data/processed data/attacks models logs

# Expose API port
EXPOSE 8000

# Start command
CMD ["python", "-m", "uvicorn", "src.api.app:app", \
     "--host", "0.0.0.0", "--port", "8000"]