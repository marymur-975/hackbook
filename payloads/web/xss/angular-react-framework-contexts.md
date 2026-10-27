---
id: xss-angular-react-framework-contexts
title: "XSS в Angular и React: bypassSecurityTrust*, dangerouslySetInnerHTML"
type: xss
target: frontend
category: web
difficulty: intermediate
bypass: none
tags: [xss, angular, react, vue, svelte, frontend-security, dompurify]
tested_on: ["Angular 17", "React 18", "Vue 3 (собственные стенды)"]
success_rate: 0.5
risk: high
cwe: "CWE-79"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
  - "https://angular.io/guide/security"
  - "https://react.dev/reference/react-dom/components/dangerously-set-inner-html"
---

# XSS в Angular и React: bypassSecurityTrust*, dangerouslySetInnerHTML

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# ── Angular ────────────────────────────────────────────────────────
# уязвимо: санитизация отключена разработчиком
#   element.innerHTML = trustedHtml;              // после bypassSecurityTrustHtml
#   this.sanitizer.bypassSecurityTrustHtml(userInput)
#   this.sanitizer.bypassSecurityTrustScript(userInput)
#   this.sanitizer.bypassSecurityTrustUrl(userInput)      // javascript: URL
#   this.sanitizer.bypassSecurityTrustResourceUrl(userInput)
#   this.sanitizer.bypassSecurityTrustStyle(userInput)
# шаблоны, которые ломают защиту:
#   <div [innerHTML]="bypassed"></div>
#   <a [href]="bypassedUrl">click</a>                   // javascript:...
#   <iframe [src]="bypassedResourceUrl"></iframe>
#   DomSanitizer + bypass в пайпе/сервисе «для удобства»
# дополнительно: динамические стили/выражения через Renderer2 и
#   ngComponentOutlet с данными пользователя; eval-подобные выражения
#   в старых версиях (template expressions)

# ── React ──────────────────────────────────────────────────────────
# уязвимо:
#   <div dangerouslySetInnerHTML={{ __html: userInput }} />
#   <a href={userInput}>                                  // javascript: URL
#       (React предупреждает, но не блокирует в ряде версий/контекстов)
#   <iframe src={userInput} />
#   element.innerHTML = userInput                         // вне React
#   href={\`javascript:${code}\`}
# безопасно: {userInput} (JSX экранирует), DOMPurify перед __html

# ── Vue ────────────────────────────────────────────────────────────
# уязвимо: v-html="userInput"    (аналог innerHTML)
# уязвимо: <component :is="userString">  при динамической компиляции шаблонов
# безопасно: {{ userInput }} (интерполяция экранирует)

# ── Svelte ─────────────────────────────────────────────────────────
# уязвимо: {@html userInput}
# безопасно: {userInput}

# ── jQuery / «старый» код рядом с фреймворком ─────────────────────
# уязвимо: $(el).html(userInput); $.parseHTML(userInput) с allowScripts
# уязвимо: $(userInput) — селектор из строки может создать узлы
# безопасно: $(el).text(userInput)

# ── проверка своего приложения (стенд) ────────────────────────────
# grep -rn "dangerouslySetInnerHTML\|bypassSecurityTrust\|v-html\|{@html\|\.innerHTML" src/
# grep -rn "javascript:" src/ | grep -v test
```

## Explanation

Фреймворки экранируют вывод по умолчанию — это правда, и большинство
XSS в SPA возникает не из-за фреймворка, а из-за **явного отключения
защиты** разработчиком:

* Angular: `DomSanitizer.bypassSecurityTrustHtml/Script/Url/ResourceUrl/Style`.
  Каждый вызов — потенциальная дыра. Особенно опасны `bypassSecurityTrustUrl`
  (пропускает `javascript:`) и `bypassSecurityTrustResourceUrl`
  (`iframe src`).
* React: `dangerouslySetInnerHTML={{__html}}` — прямой `innerHTML`.
  Отдельный класс: `href={userInput}` и `src={userInput}` — не все версии
  и не все контексты блокируют `javascript:`-схемы, поэтому валидация
  схемы должна быть в коде.
* Vue: `v-html`; Svelte: `{@html}`; jQuery: `.html()`.

Дополнительные источники XSS в SPA:

1. **URL-контексты**: `location.hash`/`search`, попадающие в `href`,
    `src`, `formaction`, `routerLink` без проверки схемы.
2. **Динамическая компиляция шаблонов**: Vue `runtime + compiler`,
    Angular `ngComponentOutlet` с пользовательскими данными, React
    `eval`-подобные решения для «живых» шаблонов.
3. **Сторонние библиотеки**: редакторы, чарты, карты, виджеты,
    которые сами пишут `innerHTML` (их код не защищён вашим фреймворком).
4. **Пост-обработка DOM**: код, который берёт HTML из API/ленты и
    вставляет без санитизации (RSS, комментарии, письма).
5. **Service Worker и кэш**: закешированный HTML с вектором
    воспроизводится без участия сервера.

Правильная модель: фреймворк экранирует — не мешайте ему; если разметка
нужна (rich text), прогоняйте через DOMPurify с жёсткой конфигурацией
и **после** этого вставляйте; URL-схемы проверяйте явно
(allowlist `http`/`https`/`mailto`/`tel`); CSP с `script-src 'self'`
и Trusted Types как второй слой.

## Detection

* Статический анализ: правила ESLint/Semgrep на
  `dangerouslySetInnerHTML`, `bypassSecurityTrust*`, `v-html`,
  `{@html}`, `.innerHTML =`, `document.write`, `eval`,
  `new Function(`, `javascript:` в строках.
* Ревью: каждый `bypassSecurityTrust*` требует обоснования в комментарии
  и ссылки на санитайзер.
* CSP-отчёты: нарушения `script-src` — индикатор успешной инъекции
  (или бага).
* DAST: сканирование SPA с векторами в каждом параметре, включая
  hash-фрагменты и поля rich text.
* Рантайм-детект (в браузере): `MutationObserver` на появление узлов
  `<script>`, `on*`-атрибутов, `javascript:`-URL — отправка beacon
  в SIEM.
* Анализ зависимостей: известные XSS в сторонних редакторах/виджетах
  (SCA + бюллетени).
* Логи сервера: запросы с векторами в параметрах, попадающих в rich text.

## Remediation

- Запретить `bypassSecurityTrust*` и `dangerouslySetInnerHTML` без
  ревью; в линтере — ошибка, не предупреждение.
- Rich text: DOMPurify с явным allowlist-конфигом (`ALLOWED_TAGS`,
  `ALLOWED_ATTR`, `FORBID_TAGS: ['style','script','iframe']`,
  `ALLOW_DATA_ATTR: false`), санитизация **после** получения HTML
  и перед вставкой; в Angular — через политику Trusted Types.
- URL: функция-валидатор схемы (allowlist `http/https/mailto/tel`),
  запрет `javascript:`/`data:`/`vbscript:`; для внешних ссылок —
  `rel="noopener noreferrer"`.
- CSP: `script-src 'self'` без `unsafe-inline`, `object-src 'none'`,
  `base-uri 'none'`, `require-trusted-types-for 'script'`, SRI для CDN.
- Изоляция недоверенного контента: отдельный origin (sandbox-домен),
  `<iframe sandbox>` без `allow-scripts` + `allow-same-origin` одновременно.
- Не использовать runtime-компиляцию шаблонов из пользовательских
  данных (Vue full build, `ngComponentOutlet` с данными пользователя).
- Тесты: негативные кейсы для каждого поля rich text; DAST в CI.
- Обучение: типовые ошибки фреймворков — часть обязательного чек-листа
  ревью (см. главу 8).

## Detection rules

```yaml
title: XSS во фреймворках — template-инъекции Angular/React/Vue в пользовательских данных
id: e5f6a7b8-0053-4e5f-9a7b-000000000053
status: experimental
description: >-
  Маркеры обхода фреймворковой санитизации: constructor.constructor(...)
  (Angular sandbox escape), dangerouslySetInnerHTML/bypassSecurityTrust/
  v-html в сохраняемом контенте или параметрах.
references:
  - https://attack.mitre.org/techniques/T1189/
logsource:
  category: webserver
  definition: 'access-лог и логи приложения с телами запросов'
detection:
  selection_query:
    cs-uri-query|contains:
      - 'constructor.constructor'
      - 'dangerouslySetInnerHTML'
      - 'bypassSecurityTrust'
      - 'ng-bind-html'
      - 'v-html='
      - '$eval('
      - '{{_c.'
  selection_body:
    request_body|contains:
      - 'constructor.constructor'
      - 'dangerouslySetInnerHTML'
      - 'bypassSecurityTrust'
      - 'ng-bind-html'
      - 'v-html='
  condition: selection_query or selection_body
fields:
  - c-ip
  - cs-uri-query
  - request_path
  - request_body
falsepositives:
  - frontend-исходники, передаваемые через API сборки (CI) — исключайте по источнику
level: high
tags:
  - attack.initial_access
  - attack.t1189
  - cwe.79
```
