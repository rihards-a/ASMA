# ASMA: the Flask application, run by gunicorn as an unprivileged user.
FROM python:3.14-slim-trixie

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

# Only the package is copied: .env, data/ and tests/ stay out of the image.
# The code stays owned by root, so the application can read and execute it,
# but not modify it.
COPY asma/ asma/
RUN chmod -R a+rX asma

# Database and job artifacts (db.py and jobs.py write under ASMA_DATA_DIR).
ENV ASMA_DATA_DIR=/data
RUN mkdir -p /data && chown asma:asma /data

USER asma
EXPOSE 8000

# Exactly one worker: the job queues live in the worker's memory, and every
# worker start marks unfinished jobs as interrupted. Threads serve parallel requests.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:8000", "asma:create_app()"]
