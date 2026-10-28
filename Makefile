.PHONY: up down migrate seed openapi worker-etl worker-sla worker-reports test lint

up:
	docker compose up -d --build

down:
	docker compose down

migrate:
	cd backend && python -m alembic upgrade head

seed:
	PYTHONPATH=backend python -m app.scripts.seed

openapi:
	PYTHONPATH=backend python -m app.scripts.generate_openapi

worker-etl:
	PYTHONPATH=backend python -m app.workers.etl_worker

worker-sla:
	PYTHONPATH=backend python -m app.workers.sla_worker

worker-reports:
	PYTHONPATH=backend python -m app.workers.report_worker

test:
	PYTHONPATH=backend pytest backend/tests -q
	cd frontend && npm test -- --run

lint:
	PYTHONPATH=backend ruff check backend/app backend/tests
	cd frontend && npm run lint
