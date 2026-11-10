FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Instalar UFW para el firewall de Linux
RUN apt-get update && apt-get install -y ufw iproute2 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV GROQ_API_KEY=""

ENTRYPOINT ["python", "soc_agent.py"]