.PHONY: ci checkformat lint install run autoformat

VENV_NAME?=venv
VENV_ACTIVATE=. $(VENV_NAME)/bin/activate
PYTHON=$(VENV_NAME)/bin/python3
PROJECT=opendrop

.DEFAULT: lint

venv: $(VENV_NAME)/bin/activate

$(VENV_NAME)/bin/activate: setup.py requirements-dev.txt Makefile
	test -d $(VENV_NAME) || virtualenv -p python3 $(VENV_NAME)
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -e .
	touch $(VENV_NAME)/bin/activate

ci: checkformat lint install

checkformat:
	$(PYTHON) -m yapf --diff -r setup.py $(PROJECT)

lint: venv	
	$(PYTHON) -m flake8 --statistics --show-source setup.py $(PROJECT)

install: venv
	$(PYTHON) -m pip install .

run: install
	$(VENV_NAME)/bin/$(PROJECT) receive

autoformat: venv
	$(PYTHON) -m yapf -i -r setup.py $(PROJECT)
