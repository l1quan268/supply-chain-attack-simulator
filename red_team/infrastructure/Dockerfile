FROM python:3.12-slim

# Cài openssl CLI để tạo self-signed cert cho SSL shell listener
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY c2_server.py .

# Tạo thư mục loot để lưu dữ liệu exfiltrate
RUN mkdir -p /app/loot

EXPOSE 8080 4444

CMD ["python", "c2_server.py"]
