SHELL := /bin/bash
.PHONY: help up down restart logs test clean

help:
	@echo "OpsDesk Security Presentation Lab"
	@echo "================================="
	@echo "Commands:"
	@echo "  make up          - Build and start containers locally (127.0.0.1:8000)"
	@echo "  make down        - Stop containers and remove volumes"
	@echo "  make restart     - Clean restart lab"
	@echo "  make logs        - Follow container logs"
	@echo "  make test        - Run test suite with pytest"
	@echo ""
	@echo "Refer to README.md for presentation walkthrough and attack demonstrations."

up:
	docker compose up --build

down:
	docker compose down -v

restart:
	docker compose down -v
	docker compose up --build -d

logs:
	docker compose logs -f

test:
	pytest -v tests/
