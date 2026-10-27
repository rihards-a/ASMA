# ASMA: the Flask application together with the scanner binaries it runs
# (nmap, puredns, massdns), so no server needs its own platform-specific copies.

# ---- Stage 1: build puredns (Go) and massdns (C) -----------------------------
# Compatible Debian Trixie release with the runtime stage - massdns is linked with glibc.
FROM golang:1.26-trixie AS builder

# Build tools for massdns. The golang image currently ships them (through
# buildpack-deps:trixie-scm); but installing them explicitly removes the dependency.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git make gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# massdns does the actual resolving for puredns.
RUN git clone --depth 1 --branch v1.1.0 https://github.com/blechschmidt/massdns.git /build/massdns \
    && make -C /build/massdns

# puredns, installed to /go/bin.
RUN go install github.com/d3mondev/puredns/v2@v2.1.1

# ---- Stage 2: runtime --------------------------------------------------------
FROM python:3.14-slim-trixie

# nmap from the Debian repositories.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# copy the files from the previous build stage.
COPY --from=builder /build/massdns/bin/massdns /go/bin/puredns /usr/local/bin/

# Unprivileged user with a static UID, so the host can grant exactly this UID
# access to the bind-mounted data directory. The home directory is used by
# gunicorn for its control socket.
RUN groupadd --gid 10001 asma \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin asma

WORKDIR /app

# Dependencies first, so a code change does not reinstall them. gunicorn is
# installed here only: outside the container the app runs with flask run.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==26.2.0

# The package keeps its folder name. The code stays owned by root, so the
# application cannot modify it, but can read and execute it.
COPY . Monolith/
RUN chmod -R a+rX Monolith

# Database and job artifacts (db.py and jobs.py write under ASMA_DATA_DIR).
ENV ASMA_DATA_DIR=/data
RUN mkdir /data && chown asma:asma /data

USER asma
EXPOSE 8000

# Exactly one worker: the job queues live in the worker's memory, and every
# worker start marks unfinished jobs as interrupted. Threads serve parallel requests.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:8000", "Monolith:create_app()"]