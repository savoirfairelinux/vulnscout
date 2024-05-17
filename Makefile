
test:
	flake8
	pytest --cov-report html --cov=src
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete
