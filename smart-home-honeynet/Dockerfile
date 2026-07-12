FROM python:3.12-slim

# SmartHoneyNet sensor container (Telnet + HTTP honeypots + detection engine).
# Runs as a non-root user; the honeypots are low-interaction and never
# execute attacker-supplied input.

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config

RUN pip install --no-cache-dir . PyYAML

RUN useradd --create-home --uid 10001 honeynet \
    && mkdir -p /var/log/honeynet /data \
    && chown -R honeynet:honeynet /var/log/honeynet /data /app
USER honeynet

ENV HONEYNET_RULES=/app/config/detection_rules.yaml
EXPOSE 2323 8080

ENTRYPOINT ["honeynet"]
CMD ["serve"]
