FROM nikolaik/python-nodejs:python3.12-nodejs20
# This include python 3.12 and nodejs 20 on bookworm distro

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

RUN mkdir -p /scan
RUN chmod -R 777 /scan

RUN pip install --no-cache-dir -r /tmp/dev.txt \
    && rm -rf /tmp/dev.txt
