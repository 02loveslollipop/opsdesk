FROM python:3.13-slim

WORKDIR /app

# Install iputils-ping for network diagnostics
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# NOTE: Deliberate vulnerability - No USER directive is declared.
# The FastAPI application runs as root (uid=0) inside the container.

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
