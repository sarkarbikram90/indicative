# Intentionally insecure Dockerfile fixture for Trivy IaC misconfiguration testing
FROM ubuntu:latest
USER root
RUN apt-get update && apt-get install -y curl
ADD https://example.com/app.tar.gz /app/
EXPOSE 22
CMD ["sh", "-c", "sleep infinity"]
