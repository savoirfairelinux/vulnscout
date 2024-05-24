
test:
	flake8
	pytest --cov-report html --cov=src
	pdoc ./src -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

test_jenkins:
	flake8
	pytest --cov=src --junitxml=./junit.xml
	pdoc ./src -o ./htmldocs
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete
