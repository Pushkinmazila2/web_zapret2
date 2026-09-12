SHELL := /bin/bash

.PHONY: build up prod down logs shell panel smoke status strategy exit psql clean

build:
	docker compose build

up:
	docker compose up -d

prod:
	docker compose up -d --pull never --remove-orphans

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

shell:
	docker compose exec gateway bash

panel:
	docker compose exec gateway python3 /opt/webzapret/panel/panel.py --check

smoke:
	docker compose up -d
	./tests/smoke.sh

status:
	curl -fsS http://127.0.0.1:$${PANEL_PORT:-8080}/api/status

strategy:
	@echo "usage: make strategy S=<strategy-id>  (see config/strategies.json)"
	@test -n "$(S)" || exit 1
	curl -fsS -X POST http://127.0.0.1:$${PANEL_PORT:-8080}/api/strategy \
	  -H 'Content-Type: application/json' -d '{"id":"$(S)"}'

exit:
	@echo "usage: make exit M=direct|socks5|ss"
	@test -n "$(M)" || exit 1
	curl -fsS -X POST http://127.0.0.1:$${PANEL_PORT:-8080}/api/exit \
	  -H 'Content-Type: application/json' -d '{"mode":"$(M)"}'

clean:
	docker compose down -v --remove-orphans
	docker image rm -f web-zapret2:stage1 2>/dev/null || true