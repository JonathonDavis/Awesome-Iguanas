FROM node:18-alpine

WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build the application for production
RUN npm run build

# Expose port 8080
EXPOSE 8080

# Preview the production build (better for production-like environment)
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "8080"]
