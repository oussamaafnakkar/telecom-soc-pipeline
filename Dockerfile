# Tools image: runs the event generators, the detection tests, and the
# end-to-end verifier. Standard library only, so there is nothing to pip install.
FROM python:3.12-slim

# Non-root user. The /data/ss7 directory is created here so that a Docker
# named volume mounted on it inherits this ownership on first use.
RUN useradd --uid 1000 --create-home app \
    && mkdir -p /data/ss7 \
    && chown -R app:app /data

WORKDIR /app
COPY generators/ generators/
COPY detections/ detections/
COPY scripts/ scripts/

USER app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Default job: write the attack and benign fixtures into /data/ss7.
CMD ["sh", "scripts/make_fixtures.sh"]
