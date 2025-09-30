FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nikto \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY common/ ./common/
COPY nikto_api/ ./nikto_api/

# Create directory for scan results
RUN mkdir -p /app/scans

# Set Python path
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

# Expose port
EXPOSE 5001

# Run application
CMD ["python", "nikto_api/app.py"]