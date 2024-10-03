# Copyright (C) 2024 Savoir-faire Linux, Inc.

FROM node:20 AS buildfront

RUN mkdir -p /frontend /src/static
WORKDIR /frontend
COPY frontend .

# Create build .env with API_URL set as blank. This way, fetch call are made to '/api/...' on same origin.
RUN echo "VITE_API_URL=\"\"" > .env

RUN npm ci && \
    npm run build


FROM alpine:3.20

RUN mkdir -p /scan/inputs /scan/tmp /scan/outputs
WORKDIR /scan

RUN apk add --no-cache bash curl git zstd icu python3 py3-pip osv-scanner asciidoctor ruby && \
    gem install asciidoctor-pdf --version 2.3.15

# Install CycloneDX
ARG CYCLONEDX_VERSION=v0.25.1
RUN curl -sSfL "https://github.com/CycloneDX/cyclonedx-cli/releases/download/$CYCLONEDX_VERSION/cyclonedx-linux-musl-x64" -o cyclonedx-cli && \
    chmod +x cyclonedx-cli && \
    mv cyclonedx-cli /usr/local/bin/

# Install Grype
ARG GRYPE_VERSION=v0.78.0
RUN curl -sSfL "https://raw.githubusercontent.com/anchore/grype/$GRYPE_VERSION/install.sh" | sh -s -- -b /usr/local/bin

# Install dependencies for python backend
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY scan.sh ./
RUN chmod +x scan.sh
COPY src ./src
COPY --from=buildfront /src/static ./src/static

RUN rm -rf /tmp/patches

LABEL org.opencontainers.image.title="VulnScout"
LABEL org.opencontainers.image.description="SFL Vulnerability Scanner"
LABEL org.opencontainers.image.authors="Savoir-faire Linux, Inc."
LABEL org.opencontainers.image.version="v0.4.1"

CMD ./scan.sh
