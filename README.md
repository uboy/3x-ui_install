# Aegis VPN Toolbox

Универсальный модульный установщик для Ubuntu 24.04, позволяющий развернуть комплексную систему обхода блокировок и управления VPN.

## Возможности
- **3x-ui Panel**: Удобное управление Xray (VLESS, Trojan, Reality).
- **OpenVPN**: Классический VPN (UDP/1194).
- **OpenConnect (ocserv)**: Имитация Cisco AnyConnect (TCP/4443).
- **AmneziaWG**: Современный протокол с защитой от DPI (UDP/51820).
- **Security Hardening**: Автоматическая настройка SSH, Fail2Ban и UFW.
- **Интерактивный UI**: Выбор компонентов через удобные меню.

## Использование
1. Скачайте проект.
2. Запустите основной скрипт от имени root:
   ```bash
   sudo bash install.sh
   ```
3. Следуйте инструкциям на экране.

## Поведение панели 3x-ui (важно)
- При включенном `Hardening` панель **не публикуется в интернет** — это штатный и безопасный режим.
- Доступ к панели выполняется через SSH-туннель.
- Потеря SSH-туннеля/SSH-сессии выглядит как "панель недоступна", даже если контейнер `3x-ui` работает нормально.

Пример туннеля:
```bash
ssh -N -L 2053:127.0.0.1:2053 <user>@<server> -p <ssh_port>
```

## Диагностика отвалов клиентов 3x-ui
Если отваливаются именно клиенты (а не веб-панель), сначала отделите проблему доступа к панели от проблемы `xray`/inbound:

```bash
docker inspect 3x-ui --format 'status={{.State.Status}} restart={{.RestartCount}} started={{.State.StartedAt}}'
docker logs 3x-ui --since 2h --timestamps | tail -n 300
journalctl -u docker --since "2 hours ago" --no-pager | tail -n 300
ss -lntp | grep -E ':2053|:443'
ufw status numbered
```

Что проверять в логах:
- `xray`, `reality`, `tls`, `handshake`, `timeout`, `killed`, `oom`, `panic`, `fatal`.

## Примечание по Reality target/SNI
- Для стабильности Reality обычно лучше использовать согласованную пару `dest` и `serverNames` (один и тот же хост-профиль).
- По умолчанию авто-создание использует совместимый профиль:
  - `dest=google.com:443`
  - `serverNames=[\"google.com\"]`
  - `flow=\"\"` (пустой, без принудительного `xtls-rprx-vision`)
- При необходимости можно переопределить через переменные окружения:
  - `REALITY_DEST`
  - `REALITY_SERVER_NAME`
  - `REALITY_FLOW`

## Структура проекта
- `install.sh` — главный оркестратор.
- `lib/` — библиотеки (API, UI, State, Utils).
- `modules/` — независимые модули установки конкретных сервисов.

## Системные требования
- ОС: Ubuntu 24.04 (Noble Numbat).
- Права root.
- Свободные порты для выбранных сервисов.
