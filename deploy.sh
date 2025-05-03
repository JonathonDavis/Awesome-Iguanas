#!/bin/bash

# Pull the latest version from git
git pull

# Build Docker images using docker-compose
docker-compose build

# Start services with zero-downtime deployment
echo "Starting services..."

# First start/update backend services
docker-compose up -d --no-deps db repairgpt vulgpt

# Then update the frontend with scale for zero-downtime
echo "Starting frontend with zero-downtime deployment..."
docker-compose up -d --scale frontend=2 --no-deps frontend

# Sleep for 30 seconds to allow the new frontend containers to start
echo "Waiting for new containers to start..."
sleep 30

# Scale down to ensure only one frontend container is running
docker-compose up -d --scale frontend=1 --no-deps frontend

# Finally, update Caddy
docker-compose up -d --no-deps caddy

# Reload Caddy to ensure it picks up any changes
docker-compose exec caddy caddy reload --config /etc/caddy/Caddyfile

echo "Deployment completed successfully!"
