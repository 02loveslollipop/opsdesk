FROM python:3.13-slim

WORKDIR /app

# Install iputils-ping for network diagnostics
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user and group (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app -m appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Restrict file permissions and ownership to appuser
RUN chown -R appuser:appgroup /app

# Place mock sensitive flag readable only by root (UID 0) in home directories (~: /app and /root)
RUN echo "FLAG{defense_in_depth_least_privilege_2026}" > /app/flag.txt && \
    echo "FLAG{defense_in_depth_least_privilege_2026}" > /root/flag.txt && \
    chown root:root /app/flag.txt /root/flag.txt && \
    chmod 0600 /app/flag.txt /root/flag.txt

# Remediated: Run container process as unprivileged user
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
