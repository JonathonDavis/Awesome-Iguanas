#!/bin/bash

echo "Setting up Awesome-Iguanas project..."

# Make sure we're in the right directory
cd /mnt/disk-2/Awesome-Iguanas

# Create Dockerfiles for each component
mkdir -p docker-setup

# Place Docker Compose file
cat > docker-compose.yml << 'EOL'
version: '3'

services:
  # Frontend service
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - "8080:8080"
    networks:
      - awesome-iguana-network
    volumes:
      - ./frontend:/app
      - node_modules_frontend:/app/node_modules

  # RepairGPT service
  repairgpt:
    build:
      context: ./RepairGPT
      dockerfile: Dockerfile
    restart: unless-stopped
    networks:
      - awesome-iguana-network
    volumes:
      - ./RepairGPT:/app
      - node_modules_repairgpt:/app/node_modules

  # VulGPT_OSV service
  vulgpt:
    build:
      context: ./VulGPT_OSV
      dockerfile: Dockerfile
    restart: unless-stopped
    networks:
      - awesome-iguana-network
    volumes:
      - ./VulGPT_OSV:/app
      - node_modules_vulgpt:/app/node_modules
    
  # Database for the application
  db:
    image: postgres:14
    restart: unless-stopped
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=iguanas
    networks:
      - awesome-iguana-network

  # Caddy for reverse proxy
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - awesome-iguana-network

networks:
  awesome-iguana-network:
    driver: bridge

volumes:
  postgres_data:
  caddy_data:
  caddy_config:
  node_modules_frontend:
  node_modules_repairgpt:
  node_modules_vulgpt:
EOL

# Create frontend Dockerfile
cat > frontend/Dockerfile << 'EOL'
FROM node:18-alpine

WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 8080

# Start the application
CMD ["npm", "start"]
EOL

# Create RepairGPT Dockerfile
cat > RepairGPT/Dockerfile << 'EOL'
FROM python:3.9-slim

WORKDIR /app

# Copy requirements.txt (create if it doesn't exist)
RUN echo "Flask==2.0.1" > requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose port 5000
EXPOSE 5000

# Default command
CMD ["python", "app.py"]
EOL

# Create VulGPT Dockerfile
cat > VulGPT_OSV/Dockerfile << 'EOL'
FROM python:3.9-slim

WORKDIR /app

# Copy requirements.txt (create if it doesn't exist)
RUN echo "Flask==2.0.1" > requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose port 5000
EXPOSE 5000

# Default command
CMD ["python", "app.py"]
EOL

# Create Caddyfile
cat > Caddyfile << 'EOL'
localhost:80 {
    # Route to frontend
    route /* {
        reverse_proxy frontend:8080
    }

    # Route to RepairGPT API
    route /api/repair/* {
        uri strip_prefix /api/repair
        reverse_proxy repairgpt:5000
    }

    # Route to VulGPT API
    route /api/vulgpt/* {
        uri strip_prefix /api/vulgpt
        reverse_proxy vulgpt:5000
    }

    # Enable compression
    encode gzip
}
EOL

# Create deployment script
cat > deploy.sh << 'EOL'
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
EOL

# Make scripts executable
chmod +x deploy.sh

echo "Setup complete! You can now run './deploy.sh' to deploy the application."
