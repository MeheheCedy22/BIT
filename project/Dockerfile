# Dockerfile for Email Spoofing Tool
FROM python:3.13-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    dnsutils \
    swaks \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a non-root user
RUN useradd -m -u 1000 emailtool && \
    chown -R emailtool:emailtool /app

USER emailtool

# Set entrypoint
ENTRYPOINT ["python3", "email_tool.py"]

# Default command
CMD ["--help"]