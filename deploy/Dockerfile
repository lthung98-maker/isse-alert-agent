# Local development / container deployment. No GPU and no credentials baked in:
# configuration arrives at runtime via the environment (see deploy/env.example).
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

# Durable dedup store lives here; mount a volume to keep it across restarts.
ENV ISSE_ALERT_DEDUP_DB=/data/alerts-seen.db
VOLUME ["/data"]

ENTRYPOINT ["isse-alerts"]
CMD ["watch"]
