FROM alpine:3.20

LABEL org.opencontainers.image.title="Project Guard - Docker EDR & Container Security" \
      org.opencontainers.image.description="Project Guard Docker Extension: Konteyner İmaj Zafiyet, Kötü Amaçlı Yazılım ve CIS Benchmark Denetleyicisi" \
      org.opencontainers.image.vendor="Project Guard Team" \
      com.docker.desktop.extension.api.version="0.3.4" \
      com.docker.extension.screenshots="" \
      com.docker.desktop.extension.icon="docker-icon.svg" \
      com.docker.extension.detailed-description="Project Guard Next-Gen EDR & Container Security extension for Docker Desktop." \
      com.docker.extension.publisher-url="https://github.com/kilic/project-guard" \
      com.docker.extension.additional-urls="" \
      com.docker.extension.changelog=""

WORKDIR /
COPY metadata.json .
COPY docker-icon.svg .
COPY docker-compose.yaml .
COPY ui /ui

CMD ["sleep", "infinity"]
