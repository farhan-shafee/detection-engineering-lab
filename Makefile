PYTHON ?= python
.PHONY: lint-rules test-logs test demo
lint-rules:
	$(PYTHON) -m detection_lab validate
test-logs:
	$(PYTHON) -m detection_lab validate
test:
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) -m detection_lab validate
	$(PYTHON) -m detection_lab demo --check
demo:
	$(PYTHON) -m detection_lab demo
