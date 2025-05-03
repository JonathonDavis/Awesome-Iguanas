# Awesome-Iguanas: Enterprise Database Vulnerability Management Solution

This repository contains Iguana's GPT, an enterprise solution for database vulnerability management.

## Quick Start

### Prerequisites
- Linux server (tested on Ubuntu/Debian)
- Docker and Docker Compose installed
- Git
- Internet connection
- Ports 80 and 443 open for web traffic
- Domain name (optional for local deployment)
- Neo4j install 
- Neo4j populated  
### One-Command Deployment

For a quick, automated deployment:

```bash
git clone https://github.com/JonathonDavis/Awesome-Iguanas.git
cd Awesome-Iguanas
sudo ./setup.sh
```

The setup script will install all dependencies, build Docker containers, and start the application.

### Manual Deployment Steps

If you prefer to deploy manually or need more control:

1. **Clone the repository**
   ```bash
   git clone https://github.com/mattjtrev/Awesome-Iguanas.git
   cd Awesome-Iguanas
   ```

2. **Configure your domain (optional)**
   
   Edit the `Caddyfile` to use your domain:
   ```bash
   nano Caddyfile
   ```
   
   Replace `localhost:80` with your domain:
   ```
   yourdomain.com {
       # Rest of configuration remains the same
   }
   ```

3. **Deploy with Docker Compose**
   ```bash
   sudo docker-compose up -d
   ```

4. **Verify deployment**
   ```bash
   sudo docker ps
   ```
   
   You should see containers running for:
   - frontend
   - repairgpt
   - vulgpt
   - db (PostgreSQL)
   - caddy (reverse proxy)

## Accessing the Application

- **With domain**: Visit https://yourdomain.com
- **Local deployment**: Visit http://localhost:8080

## Components

- **Frontend**: Vue.js-based dashboard
- **RepairGPT**: AI-powered remediation service
- **VulGPT_OSV**: Vulnerability detection service
- **Database**: PostgreSQL database for storing vulnerability data
- **Caddy**: Reverse proxy with automatic HTTPS

## Common Issues

- **Port conflicts**: Ensure ports 80, 443, and 8080 are not in use by other applications
- **DNS configuration**: If using a domain, ensure DNS A records point to your server's IP address
- **SSL certificate**: Caddy will automatically obtain certificates when domain is properly configured

## Frontend-Only Deployment

If you only want to run the frontend component (without backend services):

1. **Clone the repository**
   ```bash
   git clone https://github.com/JonathonDavis/Awesome-Iguanas.git
   cd Awesome-Iguanas/frontend
   ```

2. **Build and run the frontend container**
   ```bash
   sudo docker build -t awesome-iguanas-frontend:latest .
   sudo docker run -d -p 8080:8080 --name awesome-iguanas-frontend awesome-iguanas-frontend
   ```

3. **Access the frontend**
   - Visit http://localhost:8080 in your browser

4. **Manage the frontend container**
   ```bash
   # Stop the container
   sudo docker stop awesome-iguanas-frontend
   
   # Start the container
   sudo docker start awesome-iguanas-frontend
   
   # Remove the container (if you need to rebuild)
   sudo docker rm awesome-iguanas-frontend
   
   # View logs
   sudo docker logs awesome-iguanas-frontend
   ```

Note: Running only the frontend will provide the UI, but backend functionality like vulnerability scanning and remediation will not be available without the full deployment.

## Maintenance

- **Update the application**:
  ```bash
  cd Awesome-Iguanas
  git pull
  sudo docker-compose down
  sudo docker-compose up -d
  ```

- **View logs**:
  ```bash
  sudo docker logs awesome-iguanas_frontend_1
  sudo docker logs awesome-iguanas_caddy_1
  ```

- **Restart services**:
  ```bash
  sudo docker-compose restart
  ```
