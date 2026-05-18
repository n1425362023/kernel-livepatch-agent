.PHONY: test clean

test:
	python3 -m pytest tests/ -v

clean:
	rm -rf *.egg-info __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
