FROM node:21-alpine as build

WORKDIR /app

# Copy package.json and package-lock.json
COPY frontend/package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the frontend application code
COPY frontend/ ./

# Set default environment variables
ENV VITE_NEO4J_URI="bolt://localhost:7687" \
    VITE_NEO4J_USER="neo4j" \
    VITE_NEO4J_PASSWORD="jaguarai"

# Build the app for production
RUN npm run build

# Production stage with Nginx
FROM nginx:alpine

# Copy built files from the build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom Nginx config if needed
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]