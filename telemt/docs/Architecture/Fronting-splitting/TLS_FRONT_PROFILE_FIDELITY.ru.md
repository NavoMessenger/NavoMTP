# Fidelity TLS Front Profile

## Обзор

Этот документ описывает, как Telemt переиспользует захваченное TLS-поведение в FakeTLS server flight и как проверять результат на реальной инсталляции.

Когда включена TLS front emulation, Telemt может собирать полезное серверное TLS-поведение выбранного origin и использовать его в emulated success path. Цель здесь не в побайтном копировании origin, а в уменьшении устойчивых synthetic признаков и в том, чтобы emitted server flight был структурно ближе к захваченному profile.

## Зачем нужно это изменение

Проект уже умеет собирать полезное серверное TLS-поведение в пути TLS front fetch:

- `change_cipher_spec_count`
- `app_data_record_sizes`
- `ticket_record_sizes`

До этого изменения эмулятор использовал только часть этой информации. Из-за этого оставался разрыв между захваченным поведением origin и тем FakeTLS server flight, который реально уходил на провод.

## Что реализовано

- Эмулятор теперь воспроизводит наблюдаемое значение `ChangeCipherSpec` из полученного `behavior_profile`.
- Эмулятор теперь воспроизводит наблюдаемые размеры ticket-like tail ApplicationData records, когда доступны raw или merged TLS profile data.
- Эмулятор теперь сохраняет больше структуры профилированного encrypted flight, а не схлопывает его в более маленькую synthetic форму.
- Для профилей без raw TLS behavior по-прежнему сохраняется прежний synthetic fallback.
- Операторский `tls_new_session_tickets` по-прежнему работает как дополнительный fallback, если профиль не даёт достаточного количества tail records.

## Практическая польза

- Снижается различимость между профилированным origin TLS-поведением и эмулируемым TLS-поведением.
- Уменьшается шанс устойчивых server-flight fingerprint, вызванных фиксированным CCS count или полностью synthetic tail record sizes.
- Уже собранные TLS profile data используются лучше, без изменения MTProto logic, KDF routing или transport architecture.

## Ограничения

Этот механизм не ставит целью сделать Telemt побайтно идентичным origin server.

Он также не меняет:

- MTProto business logic;
- поведение KDF routing;
- общую transport architecture.

Практическая цель уже:

- использовать больше уже собранных profile data;
- уменьшить fixed synthetic behavior в server flight;
- сохранить валидный FakeTLS success path, одновременно меняя форму emitted traffic на проводе.

## Цели валидации

- Корректное количество эмулируемых `ChangeCipherSpec` records.
- Корректное воспроизведение наблюдаемых ticket-tail record sizes.
- Отсутствие регрессии в существующем ALPN и payload-placement behavior.

## Как проверять результат

Рекомендуемая валидация состоит из двух слоёв:

- focused unit и security tests для CCS-count replay и ticket-tail replay;
- сравнение реальных packet capture для выбранного origin и успешной FakeTLS session.

При проверке на сети ожидаемый результат такой:

- валидный FakeTLS и MTProto success path сохраняется;
- форма раннего encrypted server flight меняется, когда доступно более богатое profile data;
- изменение видно на проводе без изменения MTProto logic и transport architecture.

Такая проверка нужна для подтверждения того, что уже собранные TLS profile data используются лучше.
Она не предназначена для доказательства побайтной эквивалентности с реальным origin server.

## Как проверить на реальной инсталляции

Самая сильная практическая проверка — side-by-side trace comparison между:

- реальным TLS origin server, используемым как `mask_host`;
- Telemt FakeTLS success-path connection для того же SNI;
- при необходимости capture от разных Telemt builds или configurations.

Смысл сравнения состоит в том, чтобы посмотреть на форму server flight:

- порядок records;
- количество `ChangeCipherSpec` records;
- количество и группировку ранних encrypted `ApplicationData` records;
- размеры tail или continuation `ApplicationData` records.

## Рекомендуемое окружение

Для самой чистой проверки лучше использовать Linux host или Docker container.

Рекомендуемый setup:

1. Один экземпляр Telemt.
2. Один реальный HTTPS origin как `mask_host`.
3. Один Telegram client, настроенный на `ee` proxy link для Telemt instance.
4. `tcpdump` или Wireshark для анализа capture.

## Пошаговая процедура проверки

### 1. Подготовить origin

1. Выберите реальный HTTPS origin.
2. Установите и `censorship.tls_domain`, и `censorship.mask_host` в hostname этого origin.
3. Убедитесь, что прямой TLS request работает:

```bash
openssl s_client -connect ORIGIN_IP:443 -servername YOUR_DOMAIN </dev/null
```

### 2. Настроить Telemt

Используйте config, где включены:

- `censorship.mask = true`
- `censorship.tls_emulation = true`
- `censorship.mask_host`
- `censorship.mask_port`

Для более чистой проверки рекомендуется:

- держать `censorship.tls_new_session_tickets = 0`, чтобы результат в первую очередь зависел от fetched profile data, а не от операторских synthetic tail records;
- держать `censorship.tls_fetch.strict_route = true`, если важна более чистая provenance для captured profile data.

### 3. Обновить TLS profile data

1. Запустите Telemt.
2. Дайте ему получить TLS front profile data для выбранного домена.
3. Если `tls_front_dir` хранится persistently, убедитесь, что TLS front cache заполнен.

Сохранённые артефакты кэша полезны, но не обязательны, если packet capture уже показывает результат в runtime.

### 4. Проверить метрики состояния TLS-front profile

Если endpoint метрик включён, перед проверкой через packet capture можно быстро проверить состояние TLS-front profile:

```bash
curl -s http://127.0.0.1:9999/metrics | grep -E 'telemt_tls_front_profile|telemt_tls_fetch_profile_cache|telemt_tls_front_full_cert'
```

Метрики состояния профиля показывают runtime-состояние настроенных TLS-front доменов:

- `telemt_tls_front_profile_domains` показывает количество настроенных, экспортируемых и скрытых из-за лимита доменов.
- `telemt_tls_front_profile_info` показывает источник профиля и флаги доступных данных по каждому домену.
- `telemt_tls_front_profile_age_seconds` показывает возраст закешированного профиля.
- `telemt_tls_front_profile_app_data_records` показывает количество закешированных AppData records.
- `telemt_tls_front_profile_ticket_records` показывает количество закешированных ticket-like tail records.
- `telemt_tls_front_profile_change_cipher_spec_records` показывает закешированное количество ChangeCipherSpec records.
- `telemt_tls_front_profile_app_data_bytes` показывает общий размер закешированных AppData bytes.

Интерпретация:

- `source="merged"` или `source="raw"` означает, что используются реальные данные TLS-профиля.
- `source="default"` или `is_default="true"` означает, что домен сейчас работает на synthetic default fallback.
- `has_cert_payload="true"` означает, что certificate payload доступен для TLS emulation.
- Ненулевые AppData/ticket/CCS counters показывают захваченную форму server flight.

Пример здорового состояния:

```text
telemt_tls_front_profile_domains{status="configured"} 1
telemt_tls_front_profile_domains{status="emitted"} 1
telemt_tls_front_profile_domains{status="suppressed"} 0
telemt_tls_front_profile_info{domain="itunes.apple.com",source="merged",is_default="false",has_cert_info="true",has_cert_payload="true"} 1
telemt_tls_front_profile_age_seconds{domain="itunes.apple.com"} 20
telemt_tls_front_profile_app_data_records{domain="itunes.apple.com"} 3
telemt_tls_front_profile_ticket_records{domain="itunes.apple.com"} 1
telemt_tls_front_profile_change_cipher_spec_records{domain="itunes.apple.com"} 1
telemt_tls_front_profile_app_data_bytes{domain="itunes.apple.com"} 5240
```

Эти метрики не доказывают побайтную эквивалентность с origin. Это эксплуатационный сигнал состояния: настроенный домен действительно основан на реальных закешированных данных профиля, а не на default fallback.

### 5. Снять direct-origin trace

С отдельной клиентской машины подключитесь напрямую к origin:

```bash
openssl s_client -connect ORIGIN_IP:443 -servername YOUR_DOMAIN </dev/null
```

Capture:

```bash
sudo tcpdump -i any -w origin-direct.pcap host ORIGIN_IP and port 443
```

### 6. Снять Telemt FakeTLS success-path trace

Теперь подключитесь к Telemt через реальный Telegram client с `ee` proxy link, который указывает на Telemt instance.

`openssl s_client` полезен для direct-origin capture и для fallback sanity checks, но он не проходит успешный FakeTLS и MTProto path.

Capture:

```bash
sudo tcpdump -i any -w telemt-emulated.pcap host TELEMT_IP and port 443
```

### 7. Декодировать структуру TLS records

Используйте `tshark`, чтобы вывести record-level structure:

```bash
tshark -r origin-direct.pcap -Y "tls.record" -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e tls.record.content_type \
  -e tls.record.length
```

```bash
tshark -r telemt-emulated.pcap -Y "tls.record" -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e tls.record.content_type \
  -e tls.record.length
```

Смотрите на server flight после ClientHello:

- `22` = Handshake
- `20` = ChangeCipherSpec
- `23` = ApplicationData

### 8. Собрать сравнительную таблицу

Обычно достаточно короткой таблицы такого вида:

| Path | CCS count | AppData count in first encrypted flight | Tail AppData lengths |
| --- | --- | --- | --- |
| Origin | `N` | `M` | `[a, b, ...]` |
| Telemt build A | `...` | `...` | `...` |
| Telemt build B | `...` | `...` | `...` |

По такой таблице должно быть легко увидеть, что:

- FakeTLS success path остаётся валидным;
- ранний encrypted server flight меняется, когда переиспользуется более богатое profile data;
- результат подтверждён packet evidence.

## Пример набора capture

Один практический пример такой проверки использует:

- `origin-direct-nginx.pcap`
- `telemt-ee-before-nginx.pcap`
- `telemt-ee-after-nginx.pcap`

Практические замечания:

- `origin` снимался как прямое TLS 1.2 connection к `nginx.org`;
- `before` и `after` снимались на Telemt FakeTLS success path с реальным Telegram client;
- первый server-side FakeTLS response остаётся валидным в обоих случаях;
- сегментация раннего encrypted server flight отличается между `before` и `after`, что согласуется с лучшим использованием captured profile data;
- такой результат показывает заметный эффект на проводе без поломки success path, но не заявляет полной неотличимости от origin.

## Более сильная валидация

Для более широкой проверки повторите ту же процедуру ещё на:

1. одном CDN-backed origin;
2. одном regular nginx origin;
3. одном origin с multi-record encrypted flight и заметными ticket-like tails.

Если одно и то же направление улучшения повторится на всех трёх, уверенность в результате будет значительно выше, чем для одного origin example.
