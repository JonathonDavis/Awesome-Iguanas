FROM node:23-alpine3.20 AS builder
WORKDIR /app
COPY package*.json ./
COPY vite.config.js ./
COPY .env.production ./
COPY index.html ./
COPY public ./public
COPY src ./src

RUN npm install --frozen-lockfile
RUN npm install -g npm@latest
RUN npm run build

# Stage 2: Serve with nginx and run ollama-proxy
FROM nginx:alpine
WORKDIR /etc/nginx

# Install Node.js for running the ollama-proxy
RUN apk add --no-cache nodejs npm

# Copy the built frontend files
COPY --from=builder /app/dist /usr/share/nginx/html

# Set up the ollama-proxy
WORKDIR /ollama-proxy
COPY ollama-proxy.js ./
COPY package*.json ./
RUN npm install express http-proxy-middleware cors

# Create directory for SSL certificates
WORKDIR /etc/nginx
RUN mkdir -p /etc/nginx/ssl

# Generate self-signed SSL certificates with stronger parameters and longer validity
RUN apk add --no-cache openssl && \
    openssl req -x509 -nodes -days 825 -sha256 -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/CN=awesome-iguanas.com/O=Awesome Iguanas/C=US" \
    -addext "subjectAltName=DNS:awesome-iguanas.com,DNS:awesome-iguanasc.om,DNS:www.awesome-iguanas.com,DNS:localhost,IP:127.0.0.1" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create a startup script to run both nginx and the ollama-proxy
RUN echo '#!/bin/sh' > /start.sh && \
    echo '# Start the ollama-proxy in the background' >> /start.sh && \
    echo 'cd /ollama-proxy' >> /start.sh && \
    echo 'node ollama-proxy.js &' >> /start.sh && \
    echo '# Start nginx in the foreground' >> /start.sh && \
    echo 'nginx -g "daemon off;"' >> /start.sh && \
    chmod +x /start.sh

# Expose both HTTP and HTTPS ports
EXPOSE 80 443 3000 8080 11434 7687

CMD ["/start.sh"]