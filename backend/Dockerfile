FROM python:3.11-slim

WORKDIR /app

# OSV ingestion needs git for cloning repos; keep image slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install combined dependencies (Flask API + OSV ingestor)
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Flask API (RepairGPT) lives at /app/*.py
COPY backend/RepairGPT/ /app/

# OSV ingestor lives at /app/vulgpt_osv/
COPY backend/VulGPT_OSV/ /app/vulgpt_osv/

# Optional helper used by osv.py to load Aura config
COPY neo4j_aura_config.py /app/neo4j_aura_config.py

EXPOSE 5000

# Default: run the Flask API
CMD ["python", "app.py"]
