FROM node:18-bookworm

# Install Python 3.11 + pip alongside Node
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Node dependencies
COPY package.json ./
RUN npm install

# Install Python dependencies
COPY requirements.txt ./
RUN python3.11 -m pip install --break-system-packages -r requirements.txt

# Copy the rest of the app
COPY . .

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["node", "server.js"]
