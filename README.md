# cthunt — китайские домены из логов Certificate Transparency

Почти каждый сайт на HTTPS попадает в публичные логи Certificate Transparency (CT): с 2018 года браузеры не принимают сертификат, если его нет в логе. `cthunt` читает эти логи напрямую, достаёт из каждого сертификата имена хостов (CN + SAN) и оставляет китайские:

| Причина (`reason`) | Что ловит |
|---|---|
| `tld`   | `.cn` со всеми зонами второго уровня (`.com.cn`, `.gov.cn`, `.bj.cn` …), `.中国`, `.中國` |
| `brand` | домены китайских брендов и все их поддомены: `taobao.com`, `qq.com`, `huaweicloud.com` … ([`cthunt/brands.txt`](cthunt/brands.txt)) |
| `kw`    | ключевое слово в регистрируемом домене: `huawei`, `aliyun`, `bytedance` … |
| `org`   | любые имена из OV/EV-сертификата, выданного организации с `C=CN` (ловит китайские компании на `.com`) |

Бесплатно, без API-ключей и без зависимостей: нужен только Python 3.10+.

## Быстрый старт

```bash
git clone <this repo> && cd <repo>

# какие логи будут читаться (берётся актуальный список Google)
python -m cthunt logs --sizes

# последний 1 млн записей каждого активного лога
python -m cthunt run

# работать постоянно и забирать новые сертификаты
python -m cthunt run --follow

# сколько собрано и докуда дочитан каждый лог
python -m cthunt stats

# выгрузка
python -m cthunt export -o hosts.txt            # все хосты с поддоменами
python -m cthunt export --apex -o apex.txt      # только регистрируемые домены
python -m cthunt export --reason tld -o cn.txt  # только .cn
```

`--db` указывается до команды: `python -m cthunt --db china.db run`. По умолчанию это `cthunt.db`.

## Как набрать миллионы

Логи огромные: в одном полугодовом шарде Google Argon или Let's Encrypt лежат сотни миллионов записей. Есть три режима:

1. **Свежий срез**, по умолчанию: `--tail 1000000` от головы каждого лога. Быстро даёт сотни тысяч хостов.
2. **Полный проход** по текущим шардам: `run --from-start`. Шард покрывает все сертификаты, которые истекают в его окне, то есть все живые сайты. Это часы или дни, зависит от лимитов логов. Прогресс сохраняется в SQLite, поэтому после Ctrl+C или падения тот же запуск продолжит с места остановки.
3. **История**: `--all-shards` добавляет прошлые шарды, где лежат сайты, которые уже не продлевали сертификат.

Добор поддоменов через crt.sh, исторический поиск по всем логам:

```bash
python -m cthunt crtsh --reason brand --limit 200   # поддомены брендовых доменов из базы
python -m cthunt crtsh --domains my_apexes.txt
```

crt.sh медленный и иногда отвечает 502/таймаутом. Запросы идут с паузой (`--delay`), ошибки пропускаются.

## Настройка

```bash
# только свои зоны, без брендов
python -m cthunt run --no-brands --suffix cn --suffix hk

# только определённые логи
python -m cthunt run --only 'argon|xenon'
python -m cthunt run --log https://ct.googleapis.com/logs/us1/argon2026h2/
python -m cthunt run --log static:https://mon.willow.ct.letsencrypt.org/2026h2/

# скорость: параллельные запросы на лог и число логов одновременно
python -m cthunt run --workers 8 --parallel-logs 12
```

Бренды и ключевые слова лежат в [`cthunt/brands.txt`](cthunt/brands.txt), свой список задаётся через `--brands file.txt`. Короткие ключевые слова (`qq`, `mi`, `jd`) задавайте доменами, а не через `kw:`, иначе они совпадут с половиной интернета.

## Как это устроено

- Поддерживаются оба типа логов: классический **RFC 6962** (`get-sth` / `get-entries`) и новый **static-ct-api** (tiled, Sunlight), на который переходят Let's Encrypt и другие операторы.
- Читаются и обычные сертификаты, и precert-записи.
- DER разбирается вручную (`cthunt/der.py`): около 100 тыс. сертификатов в секунду на одном ядре. Узкое место — сеть и лимиты логов, не CPU.
- Результаты лежат в SQLite (`hosts`: name, apex, reason, source, first_seen) без дублей. В таблице `progress` хранится позиция в каждом логе.
- При 429/5xx запрос повторяется с экспоненциальной паузой и учётом `Retry-After`.

## Docker / Railway

```bash
docker build -t cthunt .
docker run -v $PWD/data:/data cthunt                   # run --follow
docker run -v $PWD/data:/data cthunt export -o /data/hosts.txt
```

## Тесты

```bash
pip install cryptography
python -m unittest tests.test_cthunt -v
```

Тесты поднимают фейковый RFC 6962-лог и фейковый tiled-лог с синтетическими сертификатами и прогоняют полный цикл.
