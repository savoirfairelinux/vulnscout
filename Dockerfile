# Copyright (C) 2024 Savoir-faire Linux, Inc.

FROM node:20 AS buildfront

RUN mkdir -p /frontend /src/static
WORKDIR /frontend
COPY frontend .

# Create build .env with API_URL set as blank. This way, fetch call are made to '/api/...' on same origin.
COPY <<EOF .env
    VITE_API_URL=""
EOF

RUN <<EOF
    npm ci
    npm run build
EOF


FROM alpine:3.20

RUN mkdir -p /scan/inputs /scan/tmp /scan/outputs
WORKDIR /scan

COPY patches /tmp/patches

RUN apk add --no-cache bash curl git zstd icu python3 py3-pip osv-scanner

# Install CycloneDX
ARG CYCLONEDX_VERSION=v0.25.1
RUN <<EOF
    curl -sSfL "https://github.com/CycloneDX/cyclonedx-cli/releases/download/$CYCLONEDX_VERSION/cyclonedx-linux-musl-x64" -o cyclonedx-cli
    chmod +x cyclonedx-cli
    mv cyclonedx-cli /usr/local/bin/
EOF

# Install Grype
ARG GRYPE_VERSION=v0.78.0
RUN curl -sSfL "https://raw.githubusercontent.com/anchore/grype/$GRYPE_VERSION/install.sh" | sh -s -- -b /usr/local/bin

# Install and patch SPDXMerge
ARG SPDXMERGE_VERSION=00c288e245d48203e898f1ea1570a5cd2a22838f
RUN <<EOF
    git clone --depth 1 "https://github.com/philips-software/SPDXMerge.git"
    cd SPDXMerge
    git checkout "$SPDXMERGE_VERSION"
    pip3 install --no-cache-dir -r requirements.txt --break-system-packages
    git -c user.name='bot' -c user.email='bot@ci.cd' am < /tmp/patches/0001-read_docs-reduce-error-when-reading-non-spdx-file.patch
EOF

# Install dependencies for python backend
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY --chmod=755 scan.sh ./
COPY src ./src
COPY --from=buildfront /src/static ./src/static

RUN rm -rf /tmp/patches

CMD ./scan.sh
