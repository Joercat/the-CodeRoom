# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    clang \
    nasm \
    libclang-dev \
    build-essential \
    pkg-config \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create templates directory if it doesn't exist
RUN mkdir -p templates

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# Expose port
EXPOSE 10000

# Run the application
CMD ["python", "app.py"]
