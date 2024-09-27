FROM python:3.11.10-bookworm AS builder

WORKDIR /app

COPY requirements.txt ./

RUN pip wheel --wheel-dir /wheels -r requirements.txt


FROM python:3.11.10-slim-bookworm

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache /wheels/* \
    && /venv/bin/pip install --no-cache dumb-init==1.2.5.post1

COPY pylon ./pylon

ENTRYPOINT ["/venv/bin/dumb-init", "--single-child", "--", "/venv/bin/python", "-m", "pylon"]
