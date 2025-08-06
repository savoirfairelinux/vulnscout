MAKEFILE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
SRC_DIR := $(MAKEFILE_DIR)../src
FRONTEND_DIR := $(MAKEFILE_DIR)../frontend

test: test_backend test_frontend

test_backend:
	flake8 $(SRC_DIR)
	mypy --config-file tox.ini $(SRC_DIR)
	pytest --cov-report html --cov=$(SRC_DIR)
	pdoc $(SRC_DIR) -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

test_frontend:
	cd $(FRONTEND_DIR) && \
	npm ci --include=dev && \
	npm test

docker_build:
	@if [ -z "${BUILD_TAG}" ]; then echo "BUILD_TAG is not set"; exit 1; fi
	docker build -t "sflinux/vulnscout:${BUILD_TAG}" .

docker_test:
	@if [ -z "${BUILD_TAG}" ]; then echo "BUILD_TAG is not set"; exit 1; fi
	docker/testDocker.sh "sflinux/vulnscout:${BUILD_TAG}"

docker_clean:
	@if [ -z "${BUILD_TAG}" ]; then echo "BUILD_TAG is not set"; exit 1; fi
	docker image rm -f "sflinux/vulnscout:${BUILD_TAG}"
