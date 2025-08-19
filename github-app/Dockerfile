FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create log directory early (owned by root initially)
RUN mkdir -p /var/log/app

# Copy requirements and install Python dependencies
COPY github-app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the copyright validation script from scripts directory
COPY scripts/copyrightcheck.py ./copyrightcheck.py
RUN chmod +x ./copyrightcheck.py

# Copy application code
COPY github-app/app.py .

# Create non-root user and ensure ownership of app and log dirs
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app /var/log/app
USER appuser

# Expose port
EXPOSE 8000

# (Optional) Define volume for persistent logs
VOLUME ["/var/log/app"]

# Run the application
CMD ["python", "app.py"]
