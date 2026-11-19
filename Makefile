.PHONY: help install train test run docker-build docker-run clean

help:
	@echo "MailGuard Automation Commands:"
	@echo "  make install      Install Python dependencies"
	@echo "  make train        Generate sample dataset & train ML models"
	@echo "  make test         Execute pytest test suite"
	@echo "  make run          Launch FastAPI server and Web UI"
	@echo "  make docker-build Build MailGuard Docker image"
	@echo "  make docker-run   Run MailGuard container on port 8000"
	@echo "  make clean        Remove compiled Python cache files"

install:
	pip install -r requirements.txt

train:
	python -m src.models.train

test:
	python -m pytest -v

run:
	python run.py

docker-build:
	docker build -t mailguard:latest .

docker-run:
	docker run -p 8000:8000 --name mailguard-app mailguard:latest

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
