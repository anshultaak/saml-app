FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    libtool \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy application code
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir lxml==4.9.3 xmlsec==1.3.13
RUN pip install --no-cache-dir -r requirements.txt

# Set Flask app environment
ENV FLASK_APP=run.py

# Run Flask
CMD ["flask", "run", "--host=0.0.0.0"]
