# VULNERABLE baseline image (v0-vulnerable) - lab use only
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# compiled WITHOUT protections so the overflow can be demonstrated
RUN gcc -shared -fPIC -O0 -fno-stack-protector -U_FORTIFY_SOURCE -o native/libparser.so native/parser.c \
 && gcc -O0 -fno-stack-protector -U_FORTIFY_SOURCE -o native/demo native/demo.c native/parser.c
EXPOSE 5000
CMD ["python", "app.py"]
