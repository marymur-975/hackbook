---
id: xxe-svg-upload-vector
title: "XXE через загружаемые файлы (SVG / DOCX / XLSX)"
type: xxe
target: xml
category: web
difficulty: intermediate
bypass: waf
tags: [xxe, upload, svg, docx]
tested_on: ["ImageMagick", "librsvg", "Java POI", "PHP SimpleXML"]
success_rate: 0.4
risk: high
cwe: "CWE-611"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
graph:
  - target: "xxe"
    type: instance_of
  - target: "file-upload"
    type: related_to
  - target: "info-disclosure"
    type: leads_to
---

# XXE через загружаемые файлы (SVG / DOCX / XLSX)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&x;</text>
</svg>
```

## Explanation

SVG — это XML, и обработчики изображений (ImageMagick, librsvg, Inkscape,
серверные конвертеры в PNG/PDF) парсят его вместе с DTD. Загрузив «картинку»,
можно прочитать файл с сервера: значение сущности отрендерится в текст изображения
или попадёт в метаданные/PDF. Аналогично работают DOCX/XLSX/PPTX (ZIP с XML внутри):
вредоносный `word/document.xml` с внешней сущностью.
Вектор часто не покрыт WAF, потому что это «просто загрузка файла».

## Detection

1. Загрузите SVG с безобидной внутренней сущностью (`&x;` -> `HBMARK`) и посмотрите,
   раскрылась ли она в конвертированном изображении/превью.
2. Затем `file:///etc/hostname` и чтение результата (превью, PDF, OCR).
3. Для DOCX: пересоберите архив с изменённым `word/document.xml`.

## Remediation

- Конвертировать загружаемые изображения в растр в изолированном воркере
  (без доступа к ФС хоста, egress закрыт).
- Отключить DTD/внешние сущности в библиотеках обработки (ImageMagick `policy.xml`:
  запретить `SVG`-MSL, `@`-include, `url`).
- Валидация/санитизация SVG (удаление `<!DOCTYPE`, скриптов, внешних ссылок).
- Хранить загрузки вне веб-корня и отдавать с `Content-Disposition: attachment`.
