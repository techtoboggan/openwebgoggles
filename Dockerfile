FROM python:3.12-slim

WORKDIR /app

COPY scripts/requirements.txt scripts/requirements.txt
RUN pip install --no-cache-dir -r scripts/requirements.txt

COPY scripts/ scripts/
COPY assets/ assets/

# Run as non-root user (CIS Docker Benchmark 4.1)
RUN groupadd -r owg && useradd -r -g owg -d /app owg && chown -R owg:owg /app
USER owg

EXPOSE 18420 18421

ENTRYPOINT ["python", "scripts/webview_server.py"]
CMD ["--data-dir", ".openwebgoggles", "--sdk-path", "assets/sdk/openwebgoggles-sdk.js"]
