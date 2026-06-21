# MTProto Proxy (Teleproxy): runbook

Пути и порты из установщика Aegis VPN Toolbox. Используется **Teleproxy v4+** — C-реализация MTProto прокси с продвинутой защитой от DPI, актуальной на 2026 год.

> **Почему не mtg?** Автор mtg 20.06.2026 заявил, что Fake-TLS на основе mtg "всё" в РФ. МТС и другие
> операторы ввели блокировку по TLS-fingerprint (JA3). Teleproxy использует fingerprint Chrome TLS 1.3,
> MSS-clamp и ServerHello emulation — всё, чего нет в mtg.

| Переменная | Путь / значение по умолчанию |
|---|---|
| Бинарник | `/opt/mtproxy/teleproxy` |
| Конфиг | `/etc/mtproxy/config.toml` |
| Сервис | `mtproxy.service` |
| Порт прокси | задаётся в установщике (default `443`) |

---

## 1. Первая установка

```bash
sudo bash install.sh
```

В меню checklist выбрать **MTProto** (пробел), ввести порт. После установки прокси работает в режиме:
- **Fake-TLS (direct mode)**: трафик маскируется под HTTPS к настоящему сайту (default `www.google.com`)
- **MSS clamp** включён по умолчанию: фрагментирует TCP-пакеты, ломая DPI-реассемблинг ТСПУ
- **Chrome TLS 1.3 fingerprint**: JA3 неотличим от Chrome

В финальном отчёте будет:
```
Сервер:   example.com:443
Секрет:   ee... (hex)
Ссылка:   tg://proxy?server=example.com&port=443&secret=ee...
```

---

## 2. Где взять tg://proxy ссылку после установки

```bash
grep MTPROXY_SECRET /root/.aegis-vpn.state | cut -d= -f2 | base64 -d
```

Собираем ссылку вручную:
```
tg://proxy?server=<DOMAIN>&port=<PORT>&secret=<MTPROXY_SECRET>
```

---

## 3. Управление секретами

Конфиг `/etc/mtproxy/config.toml`:

```toml
port = 443
direct = true
domain = "www.google.com"

[[secret]]
key = "YOUR_32_HEX_KEY"
```

Поле `key` — 16-байтовый ключ в hex (32 символа). **Не** полный ee-секрет.
Полный ee-секрет для Telegram клиента: `ee{key}{hex_encoded_domain}`.

### Генерировать новый секрет вручную:
```bash
# Генерирует сразу ee-секрет и key для конфига
/opt/mtproxy/teleproxy generate-secret www.google.com
```

Вывод:
```
ee56f48cd7017713dbec4d35c3c37b10e5676f6f676c652e636f6d   ← для tg:// ссылки
Secret for -S:  56f48cd7017713dbec4d35c3c37b10e5             ← для config.toml key
Domain:         www.google.com
```

### Смена секрета или порта:
1. Отредактируйте конфиг:
```bash
nano /etc/mtproxy/config.toml
```
2. Reload без разрыва соединений:
```bash
kill -HUP $(systemctl show -p MainPID mtproxy | cut -d= -f2)
```
Или полный перезапуск:
```bash
systemctl restart mtproxy
```

---

## 4. Выбор маскировочного домена

Домен `www.google.com` работает, но если ТСПУ заблокирует его — смените на другой:

```bash
# Хорошие варианты (не в блэклисте ТСПУ, популярны, HTTPS 443):
/opt/mtproxy/teleproxy generate-secret www.cloudflare.com
/opt/mtproxy/teleproxy generate-secret www.amazon.com
/opt/mtproxy/teleproxy generate-secret static.cdninstagram.com
```

Обновите `domain =` в конфиге и `key =` на новое значение "Secret for -S". Перезапустите сервис.
Клиентскую ссылку `tg://` нужно обновить на новый ee-секрет.

---

## 5. Мониторинг и диагностика

```bash
# Статус сервиса
systemctl status mtproxy

# Логи в реальном времени
journalctl -u mtproxy -f

# Проверка, что порт слушается
ss -tlnp | grep teleproxy

# Версия и компилятор
/opt/mtproxy/teleproxy 2>&1 | head -1

# HTTP stats (если не менял stats_port, недоступен снаружи)
curl -s http://127.0.0.1:8888/ 2>/dev/null | head -20
```

---

## 6. Быстрая проверка после установки

```bash
systemctl is-active mtproxy    # должно быть: active
ss -tlnp | grep teleproxy      # должен слушать PORT
```

Открываем ссылку `tg://proxy?...` в Telegram → появится диалог «Подключиться к прокси».

---

## 7. Ключевые отличия от mtg

| Функция | mtg v2 | Teleproxy |
|---|---|---|
| TLS fingerprint | Generic | Chrome TLS 1.3 (JA3 = Chrome) |
| MSS clamp (DPI bypass) | Нет | Да (по умолчанию) |
| ServerHello emulation | Нет | Да (live probe) |
| Dynamic Record Sizing | Частично | Да |
| Статус в РФ (июнь 2026) | Заблокирован МТС+ | Работает |
| Язык реализации | Go | C |
| Последний релиз | Апрель 2026 | Июнь 2026 |
