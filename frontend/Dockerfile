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

# Stage 2: Serve with nginx
FROM nginx:alpine
WORKDIR /etc/nginx

# Copy the built frontend files
COPY --from=builder /app/dist /usr/share/nginx/html

# Create directory for SSL certificates
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

# Expose both HTTP and HTTPS ports
EXPOSE 80 443 8080 11434 7867

CMD ["nginx", "-g", "daemon off;"]