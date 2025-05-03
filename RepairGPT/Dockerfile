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
