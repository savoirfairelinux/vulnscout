FROM nikolaik/python-nodejs:python3.13-nodejs24

RUN apt-get update && apt-get install -y --no-install-recommends \
	asciidoc \
	curl \
	git \
	ruby \
	wget \
	xz-utils \
	zstd \
	&& gem install asciidoctor-pdf --version 2.3.15 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/dev.txt /tmp/dev.txt

RUN mkdir -p /cache/vulnscout && chmod -R 777 /cache

RUN pip install --no-cache-dir -r /tmp/dev.txt \
    && rm -rf /tmp/dev.txt

# Install Docker CLI only (no daemon)
RUN apt-get update && \
    apt-get install -y ca-certificates curl gnupg lsb-release && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) \
        signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian \
        $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*
