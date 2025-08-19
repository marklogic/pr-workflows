FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (git needed for repo clone in app)
RUN apt-get update && apt-get install -y git \
    && rm -rf /var/lib/apt/lists/*

# Create log directory early
RUN mkdir -p /var/log/app

# Copy requirements and install Python dependencies
COPY github-app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code only (script fetched dynamically at runtime)
COPY github-app/app.py .

# Create non-root user and ensure ownership of app and log dirs
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app /var/log/app
USER appuser

# Expose port
EXPOSE 8000

# Persistent logs volume
VOLUME ["/var/log/app"]

# Run the application
CMD ["python", "app.py"]
