Run via Docker on Linux:
```sh
cp .env.example .env    # fill in the API keys, and add ASMA_SECRET_KEY=<random hex> so sessions survive restarts
mkdir -p data && setfacl -R -m u:10001:rwX data    # container runs as UID 10001
docker compose up -d --build
docker compose logs asma    # temporary password of "admin" on a fresh start with an empty /data folder (the check is on the PRAGMA user_version)
# if a long time has passed on a server and security updates have been added, then set it up without cache:
docker compose build --pull --no-cache && docker compose up -d

# to check whether binaries successfully installed:
docker compose exec asma sh -c 'nmap --version | head -1; command -v puredns massdns'
```

Run tests:
```sh
uv pip install -r requirements-dev.txt
uv run pytest tests
```

Readme in the works.
