FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERLLM_PROVIDER=ollama \
    CYBERLLM_MODEL=llama3.2 \
    OLLAMA_BASE_URL=http://ollama:11434

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir -e .

COPY src/ ./src/
COPY config.yaml.example ./
COPY samples/ ./samples/

RUN groupadd -r cyberllm && useradd -r -g cyberllm cyberllm \
    && mkdir -p /app/reports /app/data/corrections \
    && chown -R cyberllm:cyberllm /app

USER cyberllm

ENTRYPOINT ["cyberllm"]
CMD ["--help"]