# Stage 1: Build the frontend
FROM node:21-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY vite.config.js ./
COPY .env.production ./
COPY index.html ./
COPY public ./public
COPY src ./src
RUN npm install --frozen-lockfile
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY public /usr/share/nginx/html
# Optional: custom nginx config (uncomment if you have one)
# COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
