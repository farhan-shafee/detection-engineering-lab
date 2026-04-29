.PHONY: lint-rules test-logs test

lint-rules:
	python3 scripts/validate_rules.py

test-logs:
	python3 -m json.tool logs/sample_logs.json > /dev/null
	python3 -m json.tool logs/windows/windows_security_events.json > /dev/null

test: lint-rules test-logs
	@echo "All tests passed."
