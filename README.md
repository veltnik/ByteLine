# byteline

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)

TUN-туннель через Tailcat и надёжный чат по UDP с подтверждением доставки.
Всё в одном файле `byteline.py` — и приложение, и библиотека.

## Возможности

- 🌐 **Туннель** — TUN-адаптер + Tailcat, виртуальная сеть между двумя машинами
- 💬 **Надёжный чат** — ACK на каждое сообщение и повторная отправка при потере
- 🔁 **Дедупликация** — повторно доставленное сообщение показывается один раз
- 🖥️ **Windows и Linux** — Wintun на Windows, `/dev/net/tun` на Linux
- 🔑 **Автоповышение прав** — UAC на Windows, `sudo` на Linux
- ⚙️ **Много настроек** — IP, маска, MTU, порты, таймауты, лимит сообщения
- 🐍 **Библиотека** — `ServerConfig` / `ClientConfig` / `ChatConfig`

## Установка

```bash
pip install byteline
```

Зависимости (`pytap3` — TUN-адаптер, `tailkitty` — Tailcat) подтягиваются автоматически.

После установки появляются:

- команда `byteline` в консоли;
- модуль `byteline` для `import byteline`.

Можно и без установки, прямо из файла:

```bash
pip install -r requirements.txt
python byteline.py --help
```

### Linux

```bash
sudo apt install -y python3 python3-venv net-tools iproute2
python3 -m venv .venv
.venv/bin/pip install byteline
.venv/bin/byteline server
```

В WSL1 TUN недоступен — нужен WSL2: `wsl --set-version Debian 2`.

## Использование

### Сервер

```bash
byteline server
```

Печатает токен `tc...` и сохраняет его в `token.txt`.

#### Постоянный токен

По умолчанию токен **связан с сохранённым ключом** Tailcat и не меняется
при перезапуске сервера. Чтобы перегенерировать токен:

```bash
byteline server --rotate-key
```

Одноразовый токен (старое поведение):

```bash
byteline server --ephemeral-key
```

Дополнительно:
- `--region 303` — закрепить конкретный DERP-регион при создании ключа;
- `--short-address` — короткий токен (154 символа вместо 232).

### Клиент

```bash
byteline client <token>
# или
byteline client --server <token>
```

Токен также читается из переменной `TUNNEL_TOKEN` или из `token.txt`.

## Параметры

| Параметр | Сервер | Клиент | Назначение |
| --- | --- | --- | --- |
| `--adapter` | pytap3-server | pytap3-client | имя TUN-адаптера |
| `--virtual-ip` | 10.0.0.1 | 10.0.0.2 | IP в туннеле |
| `--peer-ip` | 10.0.0.2 | 10.0.0.1 | IP собеседника (чат) |
| `--netmask` | 255.255.255.0 | 255.255.255.0 | маска подсети |
| `--mtu` | 1200 | 1200 | MTU интерфейса |
| `--serve-port` | 9000 | 9000 | порт туннеля |
| `--chat-port` | 59999 | 59999 | порт чата (UDP) |
| `--token-file` | token.txt | token.txt | файл с токеном |
| `--check-ip` / `--no-check-ip` | вкл | вкл | проверка занятости IP пингом |
| `--ping-timeout` | 1.0 | 1.0 | таймаут ping, сек |
| `--strict-ip` | выкл | выкл | ошибка, если IP отвечает на ping |
| `--no-reliable` | — | — | отключить ACK и повторы |
| `--ack-timeout` | 1.5 | 1.5 | ожидание ACK, сек |
| `--ack-retries` | 5 | 5 | всего попыток отправки |
| `--max-message` | 900 | 900 | лимит сообщения, байт |
| `--key` | byteline | — | имя сохранённого ключа (постоянный токен) |
| `--rotate-key` | выкл | — | перегенерировать ключ и токен |
| `--ephemeral-key` | выкл | — | одноразовый токен при каждом запуске |
| `--region` | — | — | DERP-регион для ключа |
| `--short-address` | выкл | — | короткий токен без DERP-деталей |

Примеры:

```bash
byteline server --virtual-ip 10.0.0.1 --serve-port 9000
byteline client <token> --virtual-ip 10.0.0.2 --ack-timeout 2 --ack-retries 10
byteline client <token> --no-check-ip --no-reliable
```

## Как библиотека

### Простой обмен сообщениями

Самый короткий вариант — колбэк на входящие сообщения:

```python
from byteline import ChatConfig, start_chat


def on_message(message):
    print(f"<{message.sender}> {message.text}")


with start_chat(ChatConfig(peer_ip="10.0.0.1", on_message=on_message)) as chat:
    chat.send("привет")                    # отправить
    chat.send_and_wait("как дела?", 10)    # отправить и дождаться ACK
    reply = chat.receive(timeout=30)       # получить ответ программно
    print(reply.text if reply else "нет ответа")
```

Чтение сообщений циклом:

```python
from byteline import ChatConfig, start_chat

with start_chat(ChatConfig(peer_ip="10.0.0.1")) as chat:
    for message in chat.messages():
        print(f"<{message.sender}> {message.text}")
        if message.text == "пока":
            break
```

Структура входящего сообщения (`ChatMessage`):

| Поле | Описание |
| --- | --- |
| `text` | текст сообщения |
| `sender` | IP отправителя |
| `message_id` | id сообщения (для ACK) |
| `timestamp` | время получения (`time.time()`) |
| `peer_label` | подпись собеседника |

Методы `ReliableChat`:

| Метод | Описание |
| --- | --- |
| `send(text)` / `send_message(text)` | отправить сообщение, вернуть `bool` |
| `send_and_wait(text, timeout=None)` | отправить и дождаться ACK |
| `receive(timeout=None)` | получить сообщение или `None` |
| `messages()` | итератор входящих сообщений |
| `wait_pending(timeout=None)` | дождаться подтверждения всех отправленных |
| `close()` | остановить чат |

### Туннель

```python
from byteline import ServerConfig, run_server

run_server(ServerConfig(virtual_ip="10.0.0.1", console=False))
```

```python
from byteline import ClientConfig, run_client

run_client(ClientConfig(token="tc...", virtual_ip="10.0.0.2", console=False))
```

`console=False` отключает чтение из stdin — удобно, когда туннель работает
внутри программы, а сообщения обрабатываются через API чата.

### Остановка и журнал

```python
from byteline import set_logger, stop_event

stop_event.set()  # корректно остановить run_server/run_client

import logging
set_logger(lambda tag, message: logging.info("[%s] %s", tag, message))
```

### Ошибки

Все исключения библиотеки наследуются от `ByteLineError`:

```python
from byteline import ByteLineError, run_server, ServerConfig

try:
    run_server(ServerConfig())
except ByteLineError as exc:
    print("Ошибка:", exc)
```

`ConfigError`, `PrivilegesError`, `PlatformError`, `TunError`,
`IPUnavailableError`, `PortInUseError`, `TunnelError` — частные случаи.

## Структура проекта

```
byteline.py        сам файл: приложение + библиотека
setup.py           установка пакета (модуль + команда byteline)
requirements.txt   зависимости
README.md          этот файл
LICENSE            MIT
```

Установка из исходников:

```bash
git clone https://github.com/veltnik/ByteLine.git
cd ByteLine
pip install .
```

## Лицензия

MIT
