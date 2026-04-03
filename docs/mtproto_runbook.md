# MTProto Proxy: runbook

Пути и порты из установщика Aegis VPN Toolbox.

| Переменная | Путь / значение по умолчанию |
|---|---|
| Бинарник | `/opt/mtproxy/objs/bin/mtproto-proxy` |
| Конфиги | `/etc/mtproxy/` |
| Сервис | `mtproxy.service` |
| Порт прокси | задаётся в установщике (default `443`) |
| Порт статистики | `8888` (localhost only) |

---

## 1. Первая установка

```
sudo bash install.sh
```

В меню checklist выбрать **MTProto** (пробел), ввести порт. После установки в финальном отчёте будет:

```
Сервер:   example.com:443
Секрет:   dd<32 hex символа>
Ссылка:   tg://proxy?server=example.com&port=443&secret=dd...
```

Ссылка также сохраняется в `/root/.aegis-vpn.state`.

---

## 2. Где взять tg://proxy ссылку после установки

```bash
# Читаем state-файл (base64)
grep MTPROXY_SECRET /root/.aegis-vpn.state | cut -d= -f2 | base64 -d
grep PORT_MTPROXY   /root/.aegis-vpn.state | cut -d= -f2 | base64 -d
grep DOMAIN         /root/.aegis-vpn.state | cut -d= -f2 | base64 -d
```

Собираем ссылку вручную:
```
tg://proxy?server=<DOMAIN>&port=<PORT_MTPROXY>&secret=<MTPROXY_SECRET>
```

Или через journalctl — установщик выводит ссылку в финальный отчёт в stdout:
```bash
journalctl _COMM=bash --since "1 hour ago" | grep "tg://proxy"
```

---

## 3. Добавить новый секрет (новый клиент/группа)

Каждый пользователь может получить свой секрет — MTProxy принимает несколько флагов `-S`.

```bash
# Генерируем новый секрет (fake-TLS, префикс dd)
NEW_SECRET="dd$(openssl rand -hex 16)"
echo "Новый секрет: $NEW_SECRET"

# Смотрим текущий ExecStart
grep ExecStart /etc/systemd/system/mtproxy.service
```

Редактируем сервис:
```bash
systemctl edit --full mtproxy
```

В строке `ExecStart=` добавляем ещё один флаг `-S NEW_SECRET` рядом с уже имеющимся:
```
ExecStart=/opt/mtproxy/objs/bin/mtproto-proxy \
  -u _mtproxy \
  -p 8888 \
  -H 443 \
  -S ddABCDEF1234...старый... \
  -S ddNEWNEWSECRET...новый... \
  --aes-pwd /etc/mtproxy/proxy-secret /etc/mtproxy/proxy-multi.conf \
  --multithread
```

Применяем:
```bash
systemctl daemon-reload
systemctl restart mtproxy
systemctl status mtproxy
```

Ссылка для нового клиента:
```
tg://proxy?server=<DOMAIN>&port=<PORT>&secret=<NEW_SECRET>
```

---

## 4. Обновить proxy-multi.conf вручную

Telegram периодически меняет конфиг. Без обновления прокси перестаёт работать.

```bash
curl -fsSL https://core.telegram.org/getProxyConfig -o /etc/mtproxy/proxy-multi.conf
chmod 600 /etc/mtproxy/proxy-multi.conf
systemctl restart mtproxy
```

> Для автоматического обновления — см. systemd timer ниже.

---

## 5. Systemd timer для авто-обновления proxy-multi.conf

```bash
cat > /etc/systemd/system/mtproxy-update.service <<'EOF'
[Unit]
Description=Update MTProxy Telegram config
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -fsSL https://core.telegram.org/getProxyConfig -o /etc/mtproxy/proxy-multi.conf && chmod 600 /etc/mtproxy/proxy-multi.conf && systemctl restart mtproxy'
EOF

cat > /etc/systemd/system/mtproxy-update.timer <<'EOF'
[Unit]
Description=Daily MTProxy config update

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now mtproxy-update.timer
systemctl list-timers mtproxy-update.timer
```

---

## 6. Мониторинг и диагностика

```bash
# Статус сервиса
systemctl status mtproxy

# Логи в реальном времени
journalctl -u mtproxy -f

# Статистика (порт только localhost)
curl -s http://127.0.0.1:8888/stats | head -30

# Проверка, что порт слушается
ss -tlnp | grep :443

# Тест подключения к Telegram
curl -sv https://core.telegram.org/ --max-time 5
```

---

## 7. Быстрая проверка после установки

```bash
systemctl is-active mtproxy          # должно быть: active
ss -tlnp | grep mtproto-proxy        # должен слушать PORT
curl -s http://127.0.0.1:8888/stats  # статистика доступна
```

Открываем ссылку `tg://proxy?...` на телефоне → в Telegram появится диалог «Подключиться к прокси».
