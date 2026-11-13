# ASMA

Attack surface monitoring web app. Add targets, scan them by hand or on a schedule, and view the findings of each job.

Targets and scanners:
- keyword (e.g. `example`): openSquat, newly registered lookalike domains
- domain (e.g. `example.com`): Have I Been Squatted, lookalike domains
- network (CIDR or range, max 1024 addresses): Shodan, open ports and banners

Each job keeps its findings and the raw scanner output, which can be downloaded. One job per target and scanner can be queued or running at a time.

Schedules use cron expressions in UTC, e.g. `0 3 * * 1` is every Monday at 03:00.

Roles:
- operator: manages targets, schedules, jobs and users, and sees the audit log
- viewer: can only view targets, schedules and jobs

Run via Docker on Linux:
```sh
cp .env.example .env # fill in the API keys and ASMA_SECRET_KEY, so sessions survive restarts
mkdir -p data && setfacl -R -m u:10001:rwX data # container runs as UID 10001
docker compose up -d --build
docker compose logs asma # temporary password of "admin" on a fresh start with an empty /data folder (the check is on the PRAGMA user_version)
# if a long time has passed on a server and security updates have been added, then set it up without cache:
docker compose build --pull --no-cache && docker compose up -d

# to check whether binaries successfully installed:
docker compose exec asma sh -c 'nmap --version | head -1; command -v puredns massdns'
```

Open http://127.0.0.1:8000, sign in as `admin` with the temporary password and set a new one.

REST API:
```sh
# create a key under "API keys"; a read-only key (and every viewer's key) can only read
curl -H "X-API-Key: <key>" http://127.0.0.1:8000/api/targets
curl -H "X-API-Key: <key>" -H "Content-Type: application/json" \
     -d '{"target_id": 1, "scanner": "hibs"}' http://127.0.0.1:8000/api/jobs
```
- `/api/targets`, `/api/schedules`: GET, POST; `/<id>`: GET, PATCH, DELETE
- `/api/jobs`: GET, POST; `/<id>`: GET; `/<id>/cancel`: POST
- `/api/health`: no key needed

Run tests:
```sh
uv pip install -r requirements-dev.txt
uv run pytest tests
```
