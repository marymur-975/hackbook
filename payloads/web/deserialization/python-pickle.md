---
id: deserialization-python-pickle
title: "Python: pickle/shelve — выполнение кода при десериализации"
type: deserialization
target: python
category: web
difficulty: intermediate
bypass: none
tags: [deserialization, python, pickle, rce]
tested_on: ["Python 3.11 pickle", "celery (pickle-сериализатор)", "redis-кеш"]
success_rate: 0.6
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://docs.python.org/3/library/pickle.html"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "network"
    type: related_to
    description: "Redis/Celery без аутентификации = точка входа"
---

# Python: pickle/shelve — выполнение кода при десериализации

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# диагностика: pickle с безвредным маркером (НЕ шеллкод)
python3 - <<'PY'
import pickle
class Probe:
    def __reduce__(self):
        return (print, ("HB-PICKLE-DESERIALIZED",))
print(pickle.dumps(Probe()).hex())
PY
```

## Explanation

`pickle.loads()` выполняет произвольный код: протокол позволяет указать
«создать объект через вызов X с аргументами Y» (`__reduce__`), где X —
любая импортируемая функция. Достаточно, чтобы атакующий контролировал байты,
которые попадают в `pickle.loads`.

Где это встречается:

- сессии/cookie, подписанные, но не шифрованные (Flask-подобные схемы
  с pickle-сериализатором);
- кеш в Redis/Memcached, куда пишет приложение (`cache.set(user_input)`);
- очереди задач (Celery с `task_serializer='pickle'`, RQ);
- загруженные «модели» ML (`torch.load`, `joblib.load`, `sklearn` pickle) —
  отдельный массовый вектор в 2023–2025 гг.;
- RPC/межпроцессное взаимодействие, сериализованные конфиги.

Диагностика безопасна: `__reduce__` с `print`/DNS-запросом на свой collaborator
доказывает выполнение кода без вреда системе.

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Ищите в коде `pickle.loads`, `pickle.load`, `cPickle`, `shelve`, `dill`,
   `joblib.load`, `torch.load(..., weights_only=False)`.
2. Отправьте pickle с `__reduce__ -> print('HBMARK')` и поищите маркер
   в логах/ответе.
3. Признак в трафике: байты `\x80\x04\x95` (протокол 4/5) или `\x80\x02`,
   а также `(cos\nsystem\n` внутри потока.
4. Celery: проверьте `task_serializer`/`accept_content` — если `pickle` или
   `application/x-python-serialize`, брокер без аутентификации = RCE.
5. В логах: неожиданные импорты/вызовы при обработке пользовательских данных.

## Remediation

- Не десериализовать недоверенные данные pickle'ом. Заменить на JSON/MessagePack
  с валидацией схемы.
- Celery: `task_serializer='json'`, `result_serializer='json'`,
  `accept_content=['json']`; брокер с аутентификацией и в изолированной сети.
- Кеш: не хранить pickle в общих Redis/Memcached без аутентификации;
  подписывать значения (HMAC) и проверять до загрузки.
- ML-артефакты: `torch.load(..., weights_only=True)`, safetensors вместо pickle,
  проверка моделей из недоверенных источников в песочнице.
- `RestrictedUnpickler` с whitelist классов, если pickle неизбежен.
- SAST-правило на `pickle.loads(<tainted>)`; песочница процесса, egress-фильтрация.

## Variants

```
dill.loads
```

```
yaml.load (SafeLoader обязателен)
```

```
marshal.loads
```

```
jsonpickle
```

## Detection rules

```yaml
title: Python pickle во входящих данных — опкоды и ошибки восстановления классов
id: e5f6a7b8-0114-4e5f-9a7b-000000000114
status: experimental
description: >-
  Тело запроса/задачи содержит pickle-опкоды (cos, system, Reduce) или base64
  pickle (gASV...), а в логах — «Can't get attribute ... __main__» (pickle
  пытался восстановить неизвестный класс). Host-подтверждение: python-воркер
  порождает shell.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://docs.python.org/3/library/pickle.html
logsource:
  category: application
  definition: 'логи приложения с телом запроса + auditd execve на воркерах'
detection:
  selection_body:
    request_body|contains:
      - "cos\nsystem"
      - '__reduce__'
      - 'pickle.loads'
      - 'gASV'
  selection_error:
    error_message|contains:
      - "Can't get attribute"
      - 'UnpicklingError'
      - 'pickle.loads'
  worker_shell:
    EventType: EXECVE
    ParentImage|endswith:
      - /python3
      - /python
    Image|endswith:
      - /sh
      - /bash
      - /nc
  condition: selection_body or selection_error or worker_shell
fields:
  - source_ip
  - request_path
  - error_message
  - ParentImage
  - Image
falsepositives:
  - Celery/RQ-воркеры, легитимно получающие pickle из внутренней очереди —
    worker_shell исключайте по известным ParentImage+User своих воркеров
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
