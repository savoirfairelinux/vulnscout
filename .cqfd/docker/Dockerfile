FROM python:3-bookworm

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

COPY requirements-dev.txt /tmp/requirements-dev.txt

RUN pip install --no-cache-dir -r /tmp/requirements-dev.txt \
    && rm -rf /tmp/requirements-dev.txt
