# labs/Makefile — единые команды для лабораторий hackbook.
#
# make up            — поднять все веб-лаборатории (sqli, xss, upload, vuln-hub)
# make net           — поднять сетевой профиль (redis, openldap, ftp)
# make down          — остановить и удалить контейнеры
# make test          — прогнать авто-тесты всех лабораторий
# make contract      — регрессионный контракт vuln-hub (30 проверок)
# make reset         — пересоздать тома (сброс данных лабораторий)
# make native-up     — запустить лаборатории без Docker (локальный Python)
# make native-down   — остановить процессы, запущенные native-up
# make status        — состояние контейнеров и портов
# make clean         — удалить образы и тома лабораторий
#
# Все порты публикуются только на 127.0.0.1.

SHELL := /bin/bash
COMPOSE := docker compose -f docker-compose.yml
SETUP_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))setup
WEB_LABS := sqli-lab xss-lab upload-lab vuln-hub
PORTS := 8080 8081 8082 8090
ROOT_DIR := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
PID_DIR := /tmp/hackbook-labs

.DEFAULT_GOAL := help

.PHONY: help up down net test contract reset native-up native-down status clean logs

help: ## Показать справку
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Поднять веб-лаборатории (127.0.0.1:8080-8090)
	cd $(SETUP_DIR) && $(COMPOSE) build $(WEB_LABS)
	cd $(SETUP_DIR) && $(COMPOSE) up -d $(WEB_LABS)
	@$(MAKE) --no-print-directory wait
	@echo "Лаборатории:"
	@echo "  sqli-lab    http://localhost:8080"
	@echo "  xss-lab     http://localhost:8081"
	@echo "  upload-lab  http://localhost:8082"
	@echo "  vuln-hub    http://localhost:8090  (9 классов уязвимостей)"

net: ## Поднять сетевой профиль (redis-noauth, openldap, ftp)
	cd $(SETUP_DIR) && $(COMPOSE) --profile network up -d
	cd $(SETUP_DIR) && $(COMPOSE) --profile network ps

down: ## Остановить и удалить контейнеры
	cd $(SETUP_DIR) && $(COMPOSE) --profile network down

wait: ## Дождаться готовности портов
	@for port in $(PORTS); do \
		for i in $$(seq 1 30); do \
			if (exec 3<>/dev/tcp/127.0.0.1/$$port) 2>/dev/null; then \
				echo "  порт $$port готов"; break; \
			fi; sleep 1; \
		done; \
	done

test: up ## Авто-тесты карточек на всех лабораториях
	cd $(ROOT_DIR)/.. && ./tools/payload-tester.sh --lab sqli-lab
	cd $(ROOT_DIR)/.. && ./tools/payload-tester.sh --lab xss-lab
	cd $(ROOT_DIR)/.. && ./tools/payload-tester.sh --lab upload-lab
	cd $(ROOT_DIR)/.. && ./tools/payload-tester.sh --lab vuln-hub

contract: up ## Регрессионный контракт vuln-hub (selftest, 30 проверок)
	cd $(ROOT_DIR) && python3 web-labs/vuln-hub/selftest.py --base-url http://127.0.0.1:8090

reset: ## Пересоздать тома лабораторий (сброс данных)
	cd $(SETUP_DIR) && $(COMPOSE) --profile network down -v
	@echo "Тома удалены. Поднимите заново: make up"

logs: ## Логи всех лабораторий (Ctrl-C для выхода)
	cd $(SETUP_DIR) && $(COMPOSE) --profile network logs -f --tail=50

status: ## Состояние контейнеров и портов
	cd $(SETUP_DIR) && $(COMPOSE) --profile network ps
	@echo "Порты:"
	@for port in $(PORTS); do \
		if (exec 3<>/dev/tcp/127.0.0.1/$$port) 2>/dev/null; then \
			echo "  $$port — открыт"; else echo "  $$port — закрыт"; fi; \
	done

native-up: ## Запустить лаборатории локальным Python (без Docker)
	@mkdir -p $(PID_DIR) $(PID_DIR)/uploads
	cd $(ROOT_DIR)
	DB_PATH=$(PID_DIR)/sqli.db PORT=8080 \
		nohup python3 web-labs/sqli-lab/app.py > $(PID_DIR)/sqli.log 2>&1 &
	@echo $$! > $(PID_DIR)/sqli.pid
	DB_PATH=$(PID_DIR)/xss.db PORT=8081 \
		nohup python3 web-labs/xss-lab/app.py > $(PID_DIR)/xss.log 2>&1 &
	@echo $$! > $(PID_DIR)/xss.pid
	DB_PATH=$(PID_DIR)/upload.db UPLOAD_DIR=$(PID_DIR)/uploads PORT=8082 \
		nohup python3 web-labs/upload-lab/app.py > $(PID_DIR)/upload.log 2>&1 &
	@echo $$! > $(PID_DIR)/upload.pid
	DB_PATH=$(PID_DIR)/vulnhub.db DOCS_DIR=$(ROOT_DIR)/web-labs/vuln-hub/docs PORT=8090 \
		nohup python3 web-labs/vuln-hub/app.py > $(PID_DIR)/vulnhub.log 2>&1 &
	@echo $$! > $(PID_DIR)/vulnhub.pid
	@sleep 3; $(MAKE) --no-print-directory status

native-down: ## Остановить процессы, запущенные native-up
	@for f in $(PID_DIR)/*.pid; do \
		[ -f "$$f" ] || continue; \
		kill "$$(cat $$f)" 2>/dev/null && echo "остановлен $$(basename $$f .pid)" || true; \
		rm -f "$$f"; \
	done

clean: down ## Удалить образы и тома лабораторий
	cd $(SETUP_DIR) && docker image rm -f $$(docker images --filter=reference='hackbook/*' -q) 2>/dev/null || true
	rm -rf $(PID_DIR)
	@echo "Очищено."
