FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir pyyaml
# offline by default; for live: -e VT_API_KEY=... -e ABUSEIPDB_API_KEY=... and add --live
ENTRYPOINT ["python", "-m", "soar.playbook"]
