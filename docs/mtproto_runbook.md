# MTProto Proxy (mtg): runbook

Пути и порты из установщика Aegis VPN Toolbox. Используется **mtg v2** для эффективного обхода блокировок через Fake-TLS.

| Переменная | Путь / значение по умолчанию |
|---|---|
| Бинарник | `/opt/mtproxy/mtg` |
| Конфиги | `/etc/mtproxy/mtg.toml` |
| Сервис | `mtproxy.service` |
| Порт прокси | задаётся в установщике (default `443`) |

---

## 1. Первая установка

```bash
sudo bash install.sh
```

В меню checklist выбрать **MTProto** (пробел), ввести порт. После установки используется режим **Fake-TLS (Generation 3)** с секретом типа `ee`. Этот режим маскирует трафик под обычный HTTPS-запрос к популярному домену (по умолчанию `google.com`).

В финальном отчёте будет:
```
Сервер:   example.com:443
Секрет:   ee... (hex)
Ссылка:   tg://proxy?server=example.com&port=443&secret=ee...
```

Ссылка также сохраняется в `/root/.aegis-vpn.state`.

---

## 2. Где взять tg://proxy ссылку после установки

```bash
# Читаем секрет из state-файла (хранится в base64)
grep MTPROXY_SECRET /root/.aegis-vpn.state | cut -d= -f2 | base64 -d
```

Собираем ссылку вручную:
```
tg://proxy?server=<DOMAIN>&port=<PORT>&secret=<MTPROXY_SECRET>
```

---

## 3. Управление секретами и маскировкой

`mtg` v2 использует секреты, в которые "вшит" домен (SNI). Это гарантирует, что клиент и прокси используют одинаковый домен для TLS-рукопожатия.

### Генерировать новый секрет для другого домена:
```bash
/opt/mtproxy/mtg generate-secret --hex itunes.apple.com
```

### Смена секрета или порта:
1. Отредактируйте конфигурационный файл:
```bash
nano /etc/mtproxy/mtg.toml
```

Пример содержимого:
```toml
secret = "ee...ваш_секрет..."
bind-to = "0.0.0.0:443"
```

2. Перезапустите сервис:
```bash
systemctl restart mtproxy
```

---

## 4. Обновление Telegram конфигурации
В отличие от старого MTProxy, `mtg` не требует ручного обновления `proxy-multi.conf`. Он автоматически получает актуальные IP-адреса серверов Telegram.

---

## 5. Мониторинг и диагностика

```bash
# Статус сервиса
systemctl status mtproxy

# Логи в реальном времени (полезно для отладки подключений)
journalctl -u mtproxy -f

# Проверка, что порт слушается
ss -tlnp | grep mtg

# Проверка версии
/opt/mtproxy/mtg version
```

---

## 6. Быстрая проверка после установки

```bash
systemctl is-active mtproxy    # должно быть: active
ss -tlnp | grep mtg            # должен слушать PORT
```

Открываем ссылку `tg://proxy?...` в Telegram → появится диалог «Подключиться к прокси».
