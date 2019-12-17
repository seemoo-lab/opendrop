.PHONY: ci checkformat lint test run autoformat

VENV_NAME?=venv
VENV_ACTIVATE=. $(VENV_NAME)/bin/activate
PYTHON=$(VENV_NAME)/bin/python3
PROJECT=opendrop

.DEFAULT: lint

venv: $(VENV_NAME)/bin/activate

$(VENV_NAME)/bin/activate: setup.py requirements-dev.txt Makefile
	test -d $(VENV_NAME) || virtualenv -p python3 $(VENV_NAME)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -e .
	touch $(VENV_NAME)/bin/activate

ci: checkformat lint test

checkformat: venv
	$(PYTHON) -m yapf . -r --diff --exclude $(VENV_NAME)

lint: venv	
	$(PYTHON) -m flake8 . --count --show-source --statistics --exclude $(VENV_NAME)

test: venv
	$(PYTHON) -m pytest

autoformat: venv
	$(PYTHON) -m yapf . -r --in-place --exclude $(VENV_NAME)
