FROM python:3.12-slim

# TZ: "now" in the live form and Replay uses the fake business's local (Miami) time.
# PYTHONPATH lets plain `pytest` import the app and scripts packages.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv/login-triage \
    PYTEST_ADDOPTS="-p no:cacheprovider" \
    TZ=America/New_York

WORKDIR /srv/login-triage

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Files stay root-owned, read-only for the app user. /tmp stays writable for the audit file.
COPY app/ app/
COPY data/ data/
COPY scripts/ scripts/
COPY tests/ tests/

RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 triage
USER triage

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
