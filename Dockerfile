FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/ot-risk-lab

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 otrisk \
    && mkdir -p /work \
    && chown otrisk:otrisk /work

USER otrisk
WORKDIR /work

ENTRYPOINT ["ot-risk-lab"]
CMD ["--help"]
