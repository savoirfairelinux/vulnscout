
test: test_backend test_frontend

test_backend:
	flake8 ../src
	mypy --config-file tox.ini ../src
	pytest --cov-report html --cov=../src
	pdoc ../src -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

test_frontend:
	cd ../frontend && \
	npm ci --include=dev && \
	npm test

jenkins_test: jenkins_test_backend jenkins_test_frontend

jenkins_test_backend:
	flake8
	pytest --cov=src --junitxml=./junit_backend.xml
	pdoc ./src -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

jenkins_test_frontend:
	cd frontend && \
	npm ci --include=dev && \
	npm test -- --runInBand

docker_build:
	@if [ -z "${BUILD_TAG}" ]; then echo "BUILD_TAG is not set"; exit 1; fi
	docker build -t "sflinux/vulnscout:${BUILD_TAG}" .

docker_test:
	@if [ -z "${BUILD_TAG}" ]; then echo "BUILD_TAG is not set"; exit 1; fi
	docker/testDocker.sh "sflinux/vulnscout:${BUILD_TAG}"

docker_clean:
	@if [ -z "${BUILD_TAG}" ]; then echo "BUILD_TAG is not set"; exit 1; fi
	docker image rm -f "sflinux/vulnscout:${BUILD_TAG}"
