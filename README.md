# Домены китайского интернета: CT, Common Crawl, CrUX

Три независимых скрипта собирают домены китайского интернета из бесплатных источников. Каждый пишет свой Parquet в общем формате:

| Скрипт | Источник | Файл |
|---|---|---|
| `ct_collect.py`   | логи Certificate Transparency (RFC 6962 и tiled static-ct-api) | `ct_domains.parquet` |
| `cc_collect.py`   | индекс URL Common Crawl (Parquet, только нужные колонки)        | `cc_domains.parquet` |
| `crux_collect.py` | Chrome UX Report в BigQuery, `chrome-ux-report.country_cn`      | `crux_domains.parquet` |

`validate.py` проверяет файлы на соответствие схеме и ищет в них контрольный список из 20 доменов.

## Установка

```bash
pip install -r requirements.txt      # Python 3.11+
```

DuckDB-расширение `httpfs` не нужно. Скрипты читают удалённый Parquet через HTTP Range: pyarrow скачивает только нужные колонки, DuckDB фильтрует и агрегирует локально.

## Общий формат

| Поле | Тип | Что это |
|---|---|---|
| `domain` | string | eTLD+1 в punycode (tldextract + локальная копия PSL) |
| `host` | string | полное имя хоста, ключ дедупликации |
| `source` | string | `ct` / `cc` / `crux` |
| `reason` | string | `cn_tld` / `china_list` / `lang_zho` / `crux_cn` |
| `first_seen`, `last_seen` | date | первое и последнее появление в источнике |
| `hits` | int64 | CT: уникальные сертификаты; CC: страницы; CrUX: месяцы |
| `extra` | json | CT: `issuers`, `logs`; CC: `crawls`, `zho_pages`; CrUX: `rank`, `chinese`, `origins` |

Нормализация: нижний регистр, без `*.` и точки в конце, IDN переводится в punycode.

Домен считается китайским, если выполнено хотя бы одно условие:
- зона `.cn` или `.中国` (`xn--fiqs8s`);
- домен или его родитель есть в [`accelerated-domains.china.conf`](https://github.com/felixonmars/dnsmasq-china-list), список скачивается при каждом запуске;
- для CC: `content_languages` начинается с `zho`.

Если подходит несколько причин, в `reason` записывается первая по приоритету: `cn_tld`, затем `china_list`, затем `lang_zho`.

Скачанные PSL и china-list кешируются в `.cache/`. Чекпоинты лежат в `work/` (меняется через `--work`). Повторный запуск той же команды продолжает работу с места остановки, без потерь и дублей.

## 1. CT — `ct_collect.py`

```bash
# сначала замер скорости на одном логе
python ct_collect.py --logs sycamore2027h1 --tail 2000000

# все текущие шарды за 13 месяцев (порядка 46 млрд записей, это недели)
python ct_collect.py --since 13 --workers 16 --out ct_domains.parquet

# ограничить время: через 6 часов сохранить чекпоинт и выйти; потом та же команда продолжит
python ct_collect.py --hours 6

# полный прогон на VPS: docs/CT_FULL_RUN.md
```

- Список логов берётся из `log_list.json` (gstatic). Используются шарды в состоянии usable/qualified/readonly, которые ещё не истекли.
- Стартовый индекс в каждом логе находится бинарным поиском по времени записи (`--since`).
- Каждый лог обрабатывается в отдельном процессе (`--procs`, разбор упирается в CPU), внутри него работают `--workers` HTTP-запросов. На 429/5xx скрипт делает паузу с учётом `Retry-After`.
- Каждые `--chunk` записей в `work/ct/<лог>/` записывается part-файл, после этого сдвигается чекпоинт `state.json`.
- `hits` считает уникальные сертификаты (хеш издателя и серийного номера). Пара precert/cert и один сертификат в нескольких логах дают одно попадание.
- Остальные параметры: `--logs` (`all` или части имён/URL через запятую), `--tail N` (только свежие N записей), `--max-entries`, `--aggregate-only`.

**Скорость.** Tiled-логи (Let's Encrypt, Google ParcelYard/PlumbersArms) отдают около 10 тыс. записей/с на процесс, классические RFC 6962 логи Google — около 1 тыс./с. Один шард на 1,4 млрд записей — это около 1,5 суток на одном процессе. Сертификат лежит минимум в двух логах разных операторов, так что заметную часть всех имён дают несколько крупных логов.

## 2. Common Crawl — `cc_collect.py`

```bash
python cc_collect.py                               # 6 последних краулов
python cc_collect.py --crawls CC-MAIN-2026-43 --threads 12
```

- Пути к Parquet-файлам индекса берутся из `crawl-data/<CRAWL>/cc-index-table.paths.gz` (подмножество `subset=warc`, 300 файлов на краул).
- Читаются только колонки `url_host_name`, `url_host_registered_domain`, `url_host_tld`, `content_languages`, `fetch_status`. Это около 2 МБ на файл и около 600 МБ на краул вместо 160 ГБ.
- Фильтр: `fetch_status = 200` и выполнено одно из условий: `.cn`/`.中国`, china-list, язык `zho…`. Результат группируется по host.
- `first_seen`/`last_seen` — дата краула (понедельник ISO-недели из `CC-MAIN-YYYY-WW`).
- Чекпоинт: `work/cc/<crawl>/done.txt` и part-файл на каждый файл индекса.

## 3. CrUX — `crux_collect.py`

```bash
gcloud auth application-default login       # или GOOGLE_APPLICATION_CREDENTIALS=key.json
python crux_collect.py --project MY_GCP_PROJECT --dry-run   # только объём сканирования
python crux_collect.py --project MY_GCP_PROJECT --months 12
```

- Перед запуском скрипт сверяет схему: какие месяцы есть в `INFORMATION_SCHEMA.TABLES` и есть ли колонка `experimental.popularity.rank`.
- Читаются только `origin` и `rank`. Перед запросом выполняется dry run, объём печатается. Если он больше `--max-bytes` (по умолчанию 1 ТБ), скрипт останавливается.
- Сохраняются все origin. В `reason` пишется `cn_tld`/`china_list` для китайских доменов и `crux_cn` для остальных, флаг лежит в `extra.chinese`. В `extra.rank` — лучший ранг, `hits` = число месяцев.
- Чекпоинт: `work/crux/YYYYMM.parquet` на каждый месяц.

## Проверка

```bash
python validate.py ct_domains.parquet cc_domains.parquet crux_domains.parquet
```

Проверяются колонки и типы, отсутствие дублей host и NULL, допустимые `source`/`reason`, нормализация, что host лежит под domain, `first_seen <= last_seen`, `hits >= 1` и валидность JSON. Дополнительно печатаются число доменов в `.cn` и совпадения с контрольным списком (baidu.com, qq.com, sina.com.cn и т.д.).

## Дальше (вне ТЗ)

Слияние трёх файлов по `domain`, резолв DNS с фильтром по китайским IP, проверка HTTP, обогащение по ICP.

---

В `cthunt/` лежит первая версия CT-сборщика на SQLite. Из него `ct_collect.py` использует разбор DER (`cthunt/der.py`) и клиенты логов (`cthunt/ctlog.py`).
