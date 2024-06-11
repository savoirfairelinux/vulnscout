
test:
	flake8
	pytest --cov-report html --cov=src
	pdoc ./src -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

test_jenkins: test_frontend
	flake8
	pytest --cov=src --junitxml=./junit_backend.xml
	pdoc ./src -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete


test_frontend:
	cd frontend && \
	npm ci --include=dev && \
	npm test
