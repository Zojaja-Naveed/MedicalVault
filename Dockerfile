# Hardened MedVault image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# T-01: native parser compiled with stack canary, FORTIFY and full RELRO
RUN gcc -shared -fPIC -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -Wl,-z,relro,-z,now -o native/libparser.so native/parser.c

# run as an unprivileged user, never root
RUN useradd --create-home appuser && mkdir -p uploads archives \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000
# T-07: production server, no Flask debug; --preload creates the DB once
CMD ["gunicorn", "--preload", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
