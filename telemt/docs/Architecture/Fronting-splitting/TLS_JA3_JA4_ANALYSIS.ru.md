# JA3 и JA4 анализ в Telemt

Этот документ описывает, как использовать JA3/JA4 telemetry в Telemt для диагностики блокировок, которые происходят на основе TLS ClientHello, особенно JA4 TLS client fingerprint.

Цель документа практическая: помочь оператору понять, какой клиентский TLS-отпечаток реально доходит до Telemt, как он распределён по IP/CIDR/пользователям, и как отделить JA4-based фильтрацию от блокировки по IP, SNI, домену, server flight или активному сканированию.

## Коротко

JA3 и JA4 описывают форму TLS ClientHello. ClientHello отправляет клиент, поэтому JA3/JA4 в этом контексте являются fingerprint'ами клиентской TLS-реализации, а не Telemt как сервера.

Telemt собирает JA3/JA4 только из уже прочитанного полного ClientHello:

- без packet capture;
- без MITM;
- без расшифровки TLS;
- без дополнительных сетевых чтений;
- без Prometheus labels с высокой кардинальностью;
- с ограниченным in-memory TTL/cap collector.

Собранные данные доступны:

- через API: `GET /v1/runtime/tls-fingerprints`;
- через `/beobachten`, если `general.beobachten=true`.

Основная польза:

- увидеть, какие JA4 реально используют клиенты;
- понять, один ли fingerprint страдает у всех пользователей;
- отделить проблему клиента от проблемы IP/ASN/домена;
- увидеть, доходят ли проблемные соединения до Telemt вообще;
- сравнить successful TLS-auth и bad/probe поток для одного fingerprint;
- собрать evidence для последующего изменения клиента, маршрута или deployment-профиля.

## Что такое JA3

JA3 - старый и широко совместимый способ получить hash от TLS ClientHello.

JA3 строится из ClientHello fields:

```text
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```

Значения внутри полей записываются в порядке, в котором они пришли в ClientHello. GREASE values исключаются. Итоговая строка хэшируется MD5, поэтому в API есть два поля:

- `ja3` - MD5 hash;
- `ja3_raw` - исходная строка, из которой получен hash.

Практическое значение JA3 в 2026 году ограничено тем, что современные TLS-клиенты и браузерные стеки могут менять порядок extensions. Поэтому JA3 полезен как совместимый исторический сигнал, но для диагностики современных блокировок обычно важнее JA4.

## Что такое JA4

JA4 TLS client fingerprint - более структурированный fingerprint ClientHello.

JA4 в Telemt считается для TLS-over-TCP ClientHello и имеет форму:

```text
t<version><sni_marker><cipher_count><extension_count><alpn_marker>_<cipher_hash>_<extension_hash>
```

Пример:

```text
t13d1516h2_8daaf6152771_e5627efa2ab1
```

Части JA4:

| Часть | Смысл |
| --- | --- |
| `t` | TLS over TCP. Telemt сейчас не считает JA4 для QUIC/DTLS. |
| `13`, `12`, `11`, `10` | TLS version, предпочтительно из `supported_versions`. |
| `d` / `i` | Есть SNI domain (`d`) или SNI отсутствует (`i`). |
| `15` | Количество cipher suites без GREASE, capped до `99`. |
| `16` | Количество extensions без GREASE, capped до `99`. |
| `h2`, `h1`, `00` | ALPN marker: первый и последний символ первого ALPN value или `00`. |
| `cipher_hash` | SHA256 от отсортированного списка ciphers, первые 12 hex chars. |
| `extension_hash` | SHA256 от отсортированных extensions плюс signature algorithms, первые 12 hex chars. |

Важное отличие JA4 от JA3: JA4 нормализует часть полей, поэтому он устойчивее к простому изменению порядка extensions. Это делает JA4 удобным для фильтров и одновременно полезным для диагностики таких фильтров.

## Где Telemt видит ClientHello

В TLS/FakeTLS режиме Telemt получает первые bytes соединения и определяет, похоже ли оно на TLS handshake. Если record является полным ClientHello и проходит bounds checks, Telemt один раз парсит его для JA3/JA4.

Дальше возможны три исхода:

1. **Успешный MTProxy/FakeTLS клиент**
   - Telemt принимает TLS-auth;
   - fingerprint записывается в global/IP/CIDR scopes;
   - после успешной TLS-auth Telemt добавляет user scope.

2. **Bad client или probe**
   - ClientHello полный, но auth не проходит;
   - fingerprint записывается в global/IP/CIDR scopes;
   - user scope не записывается;
   - `bad_or_probe` увеличивается.

3. **Неполный или обрезанный ClientHello**
   - fingerprint не считается;
   - такие случаи остаются в существующих bad-class counters.

Если фильтр режет трафик до того, как TCP connection или ClientHello дошли до процесса Telemt, Telemt не увидит этот fingerprint. Это важнейшее диагностическое отличие: отсутствие fingerprint'а во время жалобы пользователя часто означает блокировку до приложения, а не проблему внутри Telemt.

## Включение сбора

Collector включается, когда включён хотя бы один потребитель:

```toml
[general]
beobachten = true
beobachten_minutes = 10
```

или:

```toml
[server.api]
runtime_edge_enabled = true
runtime_edge_top_n = 50
```

Практически:

- для файлового/metrics endpoint анализа достаточно `general.beobachten=true`;
- для API snapshot нужен `server.api.runtime_edge_enabled=true`;
- `general.beobachten_minutes` задаёт retention window для fingerprint buckets;
- `server.api.runtime_edge_top_n` задаёт default Top-N размер API snapshot.

## API snapshot

Endpoint:

```bash
curl -s http://127.0.0.1:9091/v1/runtime/tls-fingerprints
```

С явным лимитом:

```bash
curl -s 'http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=100'
```

Если API защищён header'ом:

```bash
curl -s \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  'http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=100'
```

Если `runtime_edge_enabled=false`, endpoint возвращает payload с:

```json
{
  "enabled": false,
  "reason": "feature_disabled"
}
```

### Структура payload

Основные поля:

| Поле | Смысл |
| --- | --- |
| `retention_secs` | Текущее TTL окно collector'а. |
| `capacity` | Максимум retained buckets. |
| `dropped_total` | Сколько новых buckets отброшено из-за cap. |
| `parse_error_total` | Сколько полных ClientHello не удалось распарсить. |
| `by_fingerprint` | Top fingerprints глобально. |
| `by_ip` | Top fingerprints по exact source IP. |
| `by_cidr` | Top fingerprints по source prefix: IPv4 `/24`, IPv6 `/56`. |
| `by_user` | Top fingerprints по authenticated user. |

Строка snapshot:

| Поле | Смысл |
| --- | --- |
| `scope` | IP, CIDR или username. В `by_fingerprint` отсутствует. |
| `ja3` | JA3 hash. |
| `ja3_raw` | Raw JA3 string. |
| `ja4` | JA4 TLS client fingerprint. |
| `ja4_raw` | Raw JA4 material. |
| `total` | Сколько полных ClientHello попало в этот bucket. |
| `auth_success` | Сколько из них успешно прошли TLS-auth. |
| `bad_or_probe` | Сколько были bad/probe после полного ClientHello. |
| `first_seen_epoch_secs` | Первый timestamp bucket'а. |
| `last_seen_epoch_secs` | Последний timestamp bucket'а. |

### Быстрый просмотр через jq

Top JA4 глобально:

```bash
curl -s http://127.0.0.1:9091/v1/runtime/tls-fingerprints \
  | jq -r '.data.data.by_fingerprint[] | [.ja4, .total, .auth_success, .bad_or_probe] | @tsv'
```

Top JA4 по пользователям:

```bash
curl -s http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=100 \
  | jq -r '.data.data.by_user[] | [.scope, .ja4, .total, .auth_success] | @tsv'
```

Top JA4 по CIDR:

```bash
curl -s http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=100 \
  | jq -r '.data.data.by_cidr[] | [.scope, .ja4, .total, .auth_success, .bad_or_probe] | @tsv'
```

Ошибки парсинга и drops:

```bash
curl -s http://127.0.0.1:9091/v1/runtime/tls-fingerprints \
  | jq '.data.data | {retention_secs, capacity, dropped_total, parse_error_total}'
```

## Beobachten output

Если включён endpoint metrics, `/beobachten` содержит обычные forensic buckets и, когда есть данные, append-only секцию TLS fingerprints:

```bash
curl -s http://127.0.0.1:9090/beobachten
```

Фрагмент:

```text
[tls_fingerprints]
retention_secs=600 capacity=65536 dropped_total=0 parse_error_total=0
[tls_fingerprints.by_fingerprint]
ja4=t13d1516h2_8daaf6152771_e5627efa2ab1 ja3=... total=42 auth_success=41 bad_or_probe=1 first_seen=... last_seen=...
[tls_fingerprints.by_cidr]
scope=203.0.113.0/24 ja4=t13d1516h2_8daaf6152771_e5627efa2ab1 ja3=... total=10 auth_success=10 bad_or_probe=0 first_seen=... last_seen=...
```

`/beobachten` удобен для быстрой операторской диагностики без API client. API удобнее для автоматической корреляции.

## Как анализировать JA4-based блокировку

### 1. Зафиксировать симптом

Перед анализом нужно записать:

- какие пользователи жалуются;
- какая версия Telegram client используется;
- какая платформа: Desktop, Android, iOS;
- какой источник сети: mobile ISP, home ISP, corporate network, country/region;
- работает ли тот же пользователь через другой network path;
- работает ли другой пользователь с того же IP/CIDR;
- видит ли Telemt новые ClientHello от проблемного пользователя в момент попытки.

JA4 без контекста почти всегда недостаточен. Фильтры часто используют сочетание:

- JA4;
- destination IP;
- SNI;
- порт;
- ASN/source network;
- rate или connection pattern;
- reputation домена/IP;
- active probing result.

### 2. Проверить, доходит ли ClientHello до Telemt

Во время попытки подключения проблемного пользователя смотрите:

```bash
curl -s 'http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=200' \
  | jq '.data.data.by_user, .data.data.by_ip, .data.data.by_cidr'
```

Интерпретация:

| Наблюдение | Вероятный вывод |
| --- | --- |
| Нет новых rows для IP/CIDR пользователя | Блокировка до Telemt: routing, firewall, ISP/DPI drop, IP block, SYN/TCP reset, UDP/TCP path issue. |
| Есть `by_ip`/`by_cidr`, но нет `by_user` | ClientHello дошёл, но TLS-auth/MTProxy layer не дошёл до успешного пользователя. Возможны bad key, probe, wrong client, active scanner, обрыв после ClientHello. |
| Есть `by_user.auth_success` | Клиентский JA4 дошёл и был принят Telemt. Если пользователь всё равно видит проблему, искать нужно дальше: relay path, Telegram upstream, quota, route mode, session cancellation, ME/direct routing. |
| Резко растёт `bad_or_probe` для одного JA4 | Вероятны сканеры или неправильные клиенты с тем же fingerprint family. |

### 3. Сравнить working и blocked случаи

Снимите snapshot во время working case и blocked case:

```bash
curl -s 'http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=500' > tls-fp-working.json
curl -s 'http://127.0.0.1:9091/v1/runtime/tls-fingerprints?limit=500' > tls-fp-blocked.json
```

Сравните:

- появился ли тот же `ja4` в blocked сети;
- меняется ли `ja4` между версиями клиента;
- меняется ли только IP/CIDR при том же `ja4`;
- есть ли `auth_success` для того же `ja4` из других сетей;
- отличается ли `bad_or_probe` между сетями.

Ключевая матрица:

| Working JA4 | Blocked JA4 | Вывод |
| --- | --- | --- |
| Same | Same, но blocked network не доходит до Telemt | Вероятна фильтрация по JA4 + destination/IP/SNI/network до приложения. |
| Same | Same, доходит и `auth_success>0` | JA4 ClientHello не является точкой отказа; искать post-auth проблему. |
| Different | Blocked только один JA4 | Вероятен client-version/platform-specific fingerprint block. |
| Same | `bad_or_probe` растёт, `auth_success=0` | Возможно, доходит не тот клиент/secret или фильтр/прокси ломает поток после ClientHello. |

### 4. Разделить client JA4 и server fingerprint

JA4 ClientHello - это клиентская сторона. Настройки Telemt вроде TLS-front server flight, `mask_host`, ticket-tail или CCS replay не меняют ClientHello, который отправляет Telegram client.

Если фильтр принимает решение строго после ClientHello, то серверные улучшения могут не помочь. В этом случае полезные действия:

- проверить обновление Telegram client;
- сравнить платформы и версии клиента;
- проверить, меняется ли JA4 на другой версии;
- проверить, блокируется ли тот же JA4 к другому destination;
- проверить, блокируется ли другой JA4 к тому же Telemt IP/SNI;
- собрать evidence для client-side fingerprint fix.

Если ClientHello проходит, а блокировка возникает после server response, тогда уже важны:

- форма FakeTLS server flight;
- TLS front profile fidelity;
- `mask_host` поведение для non-auth clients;
- certificate/provenance fallback для сканеров;
- TCP relay behavior;
- upstream route к Telegram.

### 5. Коррелировать с packet capture

Telemt collector показывает только то, что процесс увидел. Для подтверждения фильтрации до Telemt нужен внешний capture.

На сервере:

```bash
sudo tcpdump -i any -w telemt-clienthello.pcap host CLIENT_IP and port 443
```

Быстрый tshark вывод ClientHello fields:

```bash
tshark -r telemt-clienthello.pcap -Y "tls.handshake.type == 1" -T fields \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e tcp.srcport \
  -e tcp.dstport \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str
```

Если на клиентской стороне capture видит ClientHello, а серверный capture не видит, проблема в сети между клиентом и сервером. Если серверный capture видит ClientHello, но Telemt API не видит fingerprint, проверьте порт, listener, PROXY protocol, TLS record fragmentation и bounds/errors.

## Практические сценарии

### Сценарий A: один JA4 перестал работать у многих пользователей

Признаки:

- один `ja4` доминирует в жалобах;
- у разных source CIDR нет `auth_success`;
- working пользователи используют другой JA4;
- обновление клиента меняет поведение.

Вероятный вывод: фильтр на стороне сети научился распознавать конкретный ClientHello family.

Действия:

- сравнить Telegram client versions;
- проверить, не используют ли пользователи старые клиенты;
- собрать `ja4`, `ja4_raw`, platform/version, source network;
- проверить тот же client через другую сеть;
- проверить другой client version через ту же сеть.

### Сценарий B: один CIDR не работает, JA4 обычный

Признаки:

- тот же `ja4` успешно работает из других сетей;
- проблемный `/24` или `/56` не доходит до Telemt или не получает `auth_success`;
- нет общей корреляции по версии клиента.

Вероятный вывод: проблема не в JA4 alone, а в source network policy или destination reputation.

Действия:

- сменить route/VPS/IP;
- проверить port;
- проверить SNI/domain reputation;
- сравнить с другим Telemt endpoint;
- смотреть server-side packet capture.

### Сценарий C: много `bad_or_probe` на одном JA4

Признаки:

- `bad_or_probe` высокий;
- `by_user` пустой или слабый;
- source IP/CIDR разнообразные;
- попытки не соответствуют реальным пользователям.

Вероятный вывод: активное сканирование или нерелевантный TLS traffic с похожим ClientHello.

Действия:

- смотреть `/beobachten` по IP classes;
- проверить `unknown_tls_sni` и bad-client counters;
- убедиться, что fallback `mask_host` отвечает правдоподобно;
- не делать вывод о блокировке пользователей только по global `bad_or_probe`.

### Сценарий D: `auth_success` есть, но пользователь жалуется

Признаки:

- fingerprint присутствует в `by_user`;
- `auth_success` растёт;
- соединение проходит TLS-auth.

Вероятный вывод: JA4 ClientHello не является причиной отказа в этом случае.

Действия:

- проверить user enabled/disabled status;
- проверить quota;
- проверить direct/ME route;
- проверить upstream health;
- проверить runtime events;
- смотреть relay/session logs.

## Что нельзя вывести из JA3/JA4

JA3/JA4 не говорят:

- почему сеть приняла решение о блокировке;
- какой именно vendor DPI используется;
- был ли block только по JA4 или по связке JA4+IP+SNI;
- что произошло с соединением после TLS-auth;
- как выглядит server-side TLS fingerprint;
- как ведёт себя HTTP layer после TLS.

JA3/JA4 также не являются уникальной идентичностью человека. Это fingerprint клиентской TLS-реализации и её настроек. Один fingerprint может быть у большого числа пользователей.

## Ограничения collector'а Telemt

- Считается только TLS ClientHello, который полностью дошёл до Telemt.
- QUIC/DTLS/HTTP JA4 variants не собираются.
- Truncated ClientHello не fingerprint'ится.
- User scope появляется только после успешной TLS-auth.
- `by_ip` и `by_cidr` отражают source address после нормализации/PROXY protocol path, если он используется.
- Collector bounded: при большом количестве уникальных buckets возможен рост `dropped_total`.
- Retention зависит от `general.beobachten_minutes`.
- Данные runtime in-memory; это snapshot для диагностики, а не долговременное хранилище.

## Рекомендованный workflow расследования

1. Включить `runtime_edge_enabled=true` и разумный `runtime_edge_top_n`, например `100`.
2. Зафиксировать baseline в период нормальной работы.
3. Во время жалобы снять API snapshot и `/beobachten`.
4. Сравнить `by_user`, `by_ip`, `by_cidr`, `by_fingerprint`.
5. Проверить, появляется ли problematic source в Telemt вообще.
6. Если не появляется, снять packet capture на сервере и клиенте.
7. Если появляется без `auth_success`, проверить secret/client/proxy link и bad/probe counters.
8. Если появляется с `auth_success`, исключить JA4 ClientHello как primary cause и перейти к relay/upstream/runtime диагностике.
9. Если один JA4 стабильно коррелирует с block, собрать client version/platform evidence.
10. Проверить, меняет ли обновление клиента JA4 и результат подключения.

## Минимальный incident report

Для полезного отчёта по JA4-based блокировке соберите:

```text
time_window:
telemt_version:
server_ip:
server_port:
tls_domain:
mask_host:
client_platform:
client_version:
source_network:
source_ip_or_cidr:
ja4:
ja4_raw:
ja3:
total:
auth_success:
bad_or_probe:
seen_in_by_user: yes/no
seen_in_by_ip: yes/no
seen_in_by_cidr: yes/no
server_tcpdump_seen_clienthello: yes/no
client_tcpdump_sent_clienthello: yes/no
works_from_other_network: yes/no
works_with_other_client_version: yes/no
```

Этот набор обычно достаточен, чтобы отличить client fingerprint block от IP/SNI/reputation block и от post-auth проблем Telemt.

## Источники форматов

- JA3 reference: https://github.com/salesforce/ja3
- JA4 technical details: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

