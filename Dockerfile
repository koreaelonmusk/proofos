# Cloud Run container for the ProofOS verification runtime.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY proofos/ ./proofos/
COPY proofos_agent/ ./proofos_agent/
COPY proofos_service/ ./proofos_service/

# Run as a non-root user.
RUN useradd --create-home --uid 1000 proofos && chown -R proofos:proofos /app
USER proofos

# Cloud Run supplies PORT and expects the server to bind 0.0.0.0.
ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "exec uvicorn proofos_service.app:app --host 0.0.0.0 --port ${PORT}"]
