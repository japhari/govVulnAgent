FROM python:3.11-slim

WORKDIR /app

# System deps: semgrep, curl, git
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git build-essential \
    && pip install --no-cache-dir semgrep \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-download sentence-transformers embedding model for offline operation
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" || true

RUN mkdir -p /app/reports /app/data/cwe

EXPOSE 8080

CMD ["python", "main.py"]
