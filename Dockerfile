# syntax=docker/dockerfile:1.7
# ─── Étage 1 : build ────────────────────────────────────────────────
FROM python:3.12-alpine AS builder
WORKDIR /build
RUN apk add --no-cache gcc musl-dev libffi-dev
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Étage 2 : runtime ──────────────────────────────────────────────
FROM python:3.12-alpine AS runtime

RUN addgroup -g 1001 -S soc && adduser -u 1001 -S soc -G soc

COPY --from=builder /install /usr/local
WORKDIR /app
COPY --chown=soc:soc soc_autopilot/ ./soc_autopilot/
COPY --chown=soc:soc playbooks/ ./playbooks/

USER 1001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

ENTRYPOINT ["uvicorn", "soc_autopilot.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
