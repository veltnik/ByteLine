"""ByteLine: TUN-туннель через Tailcat и надёжный чат по UDP.

Один файл — и приложение, и библиотека (Windows и Linux).

Установка как библиотеки::

    pip install .
    # или из репозитория
    pip install git+https://github.com/veltnik/ByteLine

Запуск из консоли (после установки появляется команда ``byteline``)::

    byteline server
    byteline client <token>
    byteline client --server <token> --virtual-ip 10.0.0.2

    # без установки, прямо из файла
    python byteline.py server

Простой обмен сообщениями из Python::

    from byteline import ChatConfig, start_chat

    def on_message(message):
        print(f"<{message.sender}> {message.text}")

    with start_chat(
        ChatConfig(peer_ip="10.0.0.1", on_message=on_message)
    ) as chat:
        chat.send("привет")                  # отправить
        chat.send_and_wait("как дела?", 10)  # отправить и дождаться ACK
        reply = chat.receive(timeout=30)     # получить ответ программно
        print(reply.text if reply else "нет ответа")

Только туннель, без чата::

    from byteline import ServerConfig, run_server

    run_server(ServerConfig(virtual_ip="10.0.0.1", console=False))

    from byteline import ClientConfig, run_client

    run_client(ClientConfig(token="tc...", virtual_ip="10.0.0.2", console=False))

Остановка из другого потока::

    from byteline import stop_event
    stop_event.set()

Без прав администратора приложение само перезапускается:
на Windows — через UAC, на Linux/macOS — через sudo.
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import queue
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from pytap3 import TapDevice, TapDeviceError
from tailkitty import BackendNotFound, Client, ServerProcess, ServerStartError

__version__ = "0.2.0"

IS_WINDOWS = os.name == "nt"
IFNAMSIZ = 16  # Linux: имя интерфейса вместе с завершающим NUL
ELEVATED_FLAG = "--elevated-attempt"
TOKEN_ENV = "TUNNEL_TOKEN"

NETMASK = "255.255.255.0"
DEFAULT_MTU = 1200
DEFAULT_SERVE_PORT = 9000
DEFAULT_CHAT_PORT = 59999
DEFAULT_SERVER_IP = "10.0.0.1"
DEFAULT_CLIENT_IP = "10.0.0.2"
DEFAULT_TOKEN_FILE = "token.txt"


# ---------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------


class ByteLineError(Exception):
    """Базовая ошибка ByteLine: достаточно ловить её одну."""


class ConfigError(ByteLineError):
    """Некорректные параметры конфигурации."""


class PrivilegesError(ByteLineError):
    """Не удалось получить права администратора."""


class PlatformError(ByteLineError):
    """Платформа не поддерживает TUN (например, WSL1) или нет утилит."""


class TunError(ByteLineError):
    """Не удалось создать или настроить TUN-адаптер."""


class IPUnavailableError(ByteLineError):
    """Выбранный IP-адрес некорректен или занят."""


class PortInUseError(ByteLineError):
    """Порт уже занят другим процессом."""


class TunnelError(ByteLineError):
    """Ошибка запуска или работы туннеля."""


# ---------------------------------------------------------------------------
# Журнал и общий флаг остановки
# ---------------------------------------------------------------------------

#: Взведите это событие, чтобы корректно остановить run_server/run_client.
stop_event = threading.Event()

_logger: Callable[[str, str], None] | None = None


def log(tag: str, message: str) -> None:
    """Печатает строку журнала в формате ``[тег] сообщение``."""
    if _logger is not None:
        _logger(tag, message)
        return
    print(f"[{tag}] {message}", flush=True)


def set_logger(logger: Callable[[str, str], None] | None) -> None:
    """Подменяет приёмник журнала. ``None`` возвращает вывод в stdout."""
    global _logger
    _logger = logger


# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------


@dataclass
class TunnelConfig:
    """Настройки туннеля и чата, общие для сервера и клиента."""

    adapter: str = "pytap3"
    virtual_ip: str = DEFAULT_SERVER_IP
    netmask: str = NETMASK
    mtu: int = DEFAULT_MTU
    serve_port: int = DEFAULT_SERVE_PORT
    chat_port: int = DEFAULT_CHAT_PORT
    peer_ip: str = DEFAULT_CLIENT_IP
    token_file: str | Path = DEFAULT_TOKEN_FILE

    # Проверка занятости IP
    check_ip: bool = True
    ping_timeout: float = 1.0
    strict_ip: bool = False

    # Доставка сообщений
    reliable: bool = True
    ack_timeout: float = 1.5
    ack_retries: int = 5
    max_message: int = 900

    # Читать сообщения из stdin и отправлять их собеседнику
    console: bool = True

    def validate(self) -> None:
        """Проверяет параметры и выбрасывает :class:`ConfigError`."""
        if self.ack_timeout <= 0:
            raise ConfigError("ack_timeout должен быть больше 0.")
        if self.ack_retries < 1:
            raise ConfigError("ack_retries должен быть не меньше 1.")
        if not 1 <= self.max_message <= 1100:
            raise ConfigError(
                "max_message должен быть в диапазоне 1..1100 байт "
                "(ограничение MTU туннеля)."
            )
        if self.ping_timeout <= 0:
            raise ConfigError("ping_timeout должен быть больше 0.")
        if not 0 < self.mtu <= 65535:
            raise ConfigError("mtu должен быть в диапазоне 1..65535.")
        if not 0 < self.serve_port <= 65535:
            raise ConfigError("serve_port должен быть в диапазоне 1..65535.")
        if not 0 < self.chat_port <= 65535:
            raise ConfigError("chat_port должен быть в диапазоне 1..65535.")


@dataclass
class ServerConfig(TunnelConfig):
    """Настройки сервера (сторона с публичным адресом Tailcat)."""

    adapter: str = "pytap3-server"
    virtual_ip: str = DEFAULT_SERVER_IP
    peer_ip: str = DEFAULT_CLIENT_IP


@dataclass
class ClientConfig(TunnelConfig):
    """Настройки клиента. ``token`` — адрес сервера ``tc...``."""

    adapter: str = "pytap3-client"
    virtual_ip: str = DEFAULT_CLIENT_IP
    peer_ip: str = DEFAULT_SERVER_IP
    token: str = ""


@dataclass
class ChatMessage:
    """Входящее сообщение чата."""

    text: str
    sender: str
    message_id: str = ""
    timestamp: float = 0.0
    peer_label: str = ""

    def __str__(self) -> str:
        return f"<{self.sender}> {self.text}"


@dataclass
class ChatConfig:
    """Настройки надёжного UDP-чата.

    ``on_message`` вызывается из фонового потока на каждое входящее
    сообщение. ``queue_messages`` складывает их в очередь, которую можно
    читать через :meth:`ReliableChat.receive` или :meth:`ReliableChat.messages`.
    """

    chat_port: int = DEFAULT_CHAT_PORT
    peer_ip: str = DEFAULT_CLIENT_IP
    peer_label: str = "Собеседник"
    reliable: bool = True
    ack_timeout: float = 1.5
    ack_retries: int = 5
    max_message: int = 900
    bind_ip: str = "0.0.0.0"
    console: bool = False
    on_message: Callable[["ChatMessage"], None] | None = None
    queue_messages: bool = True


# ---------------------------------------------------------------------------
# Права администратора и проверка платформы
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    """True, если процесс запущен с правами администратора/root."""
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except AttributeError:
            return True
    return os.geteuid() == 0


def _launch_command(extra: list[str]) -> list[str]:
    """Собирает команду для запуска того же приложения с аргументами."""
    entry = os.path.abspath(sys.argv[0])
    if entry.endswith((".py", ".pyw")):
        return [sys.executable, entry, *extra]
    if os.path.isfile(entry):
        return [entry, *extra]
    return [sys.executable, "-m", "byteline", *extra]


def relaunch_as_admin(argv: list[str] | None = None) -> None:
    """Перезапускает приложение с правами администратора.

    Windows — через UAC, Linux/macOS — через ``sudo``. Управление не
    возвращается: функция либо завершает процесс, либо выбрасывает
    :class:`PrivilegesError`.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if ELEVATED_FLAG in args:
        hint = (
            "запустите терминал от имени администратора."
            if IS_WINDOWS
            else "запустите от root: sudo byteline ..."
        )
        raise PrivilegesError(f"Не удалось получить права администратора: {hint}")

    command = _launch_command([ELEVATED_FLAG, *args])

    if IS_WINDOWS:
        params = subprocess.list2cmdline(command[1:])
        log("Права", "Запрашиваю права администратора (UAC)...")
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", command[0], params, os.getcwd(), 1
        )
        if rc <= 32:
            raise PrivilegesError(
                "Не удалось перезапустить с правами администратора (UAC отклонён?)."
            )
        raise SystemExit(0)

    log("Права", "Запрашиваю права root через sudo...")
    try:
        os.execvpe("sudo", ["sudo", "-E", *command], os.environ.copy())
    except OSError as exc:
        raise PrivilegesError(f"Не удалось перезапустить через sudo: {exc}") from exc


def require_admin(argv: list[str] | None = None) -> None:
    """Требует права администратора, при необходимости перезапуская процесс."""
    if not is_admin():
        relaunch_as_admin(argv)


def check_platform_support() -> None:
    """Проверяет, что TUN доступен на этой системе.

    Выбрасывает :class:`PlatformError` с подсказкой, чего не хватает.
    """
    if IS_WINDOWS:
        return
    if not os.path.exists("/dev/net/tun"):
        raise PlatformError(
            "Нет /dev/net/tun. В WSL1 TUN недоступен — переведите дистрибутив на WSL2 "
            "(wsl --set-version <distro> 2) или используйте обычный Linux. "
            "На обычном Linux: sudo mknod /dev/net/tun c 10 200 && sudo chmod 666 /dev/net/tun"
        )
    if shutil.which("ifconfig") is None:
        raise PlatformError(
            "Не найдена утилита ifconfig (нужна pytap3): sudo apt install net-tools"
        )
    if shutil.which("ip") is None:
        raise PlatformError("Не найдена утилита ip: sudo apt install iproute2")


# ---------------------------------------------------------------------------
# IP-адреса: ping, проверка занятости, маршрут подсети
# ---------------------------------------------------------------------------


def ping_ip(ip: str, timeout_s: float = 1.0) -> bool | None:
    """Проверяет адрес пингом.

    Возвращает ``True``, если адрес отвечает, ``False`` — если нет,
    ``None`` — если утилита ``ping`` недоступна.
    """
    if IS_WINDOWS:
        args = ["ping", "-n", "1", "-w", str(max(1, int(timeout_s * 1000))), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_s)))), ip]
    try:
        result = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return result.returncode == 0


def is_local_ip(ip: str) -> bool:
    """True, если адрес уже назначен одному из локальных интерфейсов."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def ensure_ip_available(
    ip: str,
    check: bool = True,
    timeout_s: float = 1.0,
    strict: bool = False,
) -> None:
    """Проверяет, что адрес корректен и, по возможности, свободен.

    Args:
        ip: адрес для проверки.
        check: выполнять ли проверку занятости.
        timeout_s: таймаут ping, секунды.
        strict: если True, отвечающий на ping адрес считается ошибкой,
            иначе выводится только предупреждение.

    Raises:
        IPUnavailableError: некорректный адрес или (при ``strict``) занятый.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise IPUnavailableError(f"Некорректный IP-адрес: {ip}") from exc

    if not check:
        log("IP", f"Проверка занятости {ip} отключена.")
        return

    if is_local_ip(ip):
        log(
            "IP",
            f"{ip} уже назначен локальному интерфейсу — похоже на остаток прошлого "
            "запуска. Продолжаю (адаптер переиспользуется).",
        )
        return

    log("IP", f"Проверяю, свободен ли {ip} (ping, таймаут {timeout_s:g} с)...")
    answer = ping_ip(ip, timeout_s)
    if answer is None:
        log("IP", "Утилита ping не найдена — проверку занятости пропускаю.")
        return
    if answer is False:
        log("IP", f"{ip} не отвечает — адрес свободен.")
        return

    message = (
        f"IP {ip} отвечает на ping: адрес может быть занят (например, роутером в вашей "
        "сети). Выберите другой virtual_ip, отключите проверку (check_ip=False) "
        "или разрешите запуск (strict_ip=False)."
    )
    if strict:
        raise IPUnavailableError(message)
    log("IP", f"ВНИМАНИЕ: {message}")
    log("IP", "Продолжаю запуск, потому что строгая проверка не включена.")


def ensure_subnet_route(adapter: str, virtual_ip: str, netmask: str = NETMASK) -> None:
    """Добавляет маршрут подсети через интерфейс адаптера."""
    try:
        network = ipaddress.ip_network(f"{virtual_ip}/{netmask}", strict=False)
    except ValueError as exc:
        raise IPUnavailableError(f"Некорректная маска {netmask}: {exc}") from exc
    subnet = str(network)
    if IS_WINDOWS:
        args = [
            "netsh", "interface", "ipv4", "add", "route", subnet,
            f"interface={adapter}", "nexthop=0.0.0.0",
            "metric=1", "store=active",
        ]
    else:
        args = ["ip", "route", "add", subnet, "dev", adapter]
    try:
        result = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        log("TUN", f"Команда {args[0]} не найдена — маршрут не добавлен.")
        return
    if result.returncode != 0:
        log("TUN", "Маршрут уже существует (это нормально).")


# ---------------------------------------------------------------------------
# TUN-адаптер и перекачка пакетов
# ---------------------------------------------------------------------------


def read_exact(stream: BinaryIO, size: int) -> bytes | None:
    """Читает ровно ``size`` байт или возвращает None при конце потока."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def pipe_to_tap(reader: BinaryIO, tap: TapDevice, mtu: int = DEFAULT_MTU) -> None:
    """Переносит пакеты из потока (tailcat) в TUN-адаптер."""
    while not stop_event.is_set():
        try:
            header = read_exact(reader, 2)
            if header is None:
                log("Туннель->TUN", "Соединение закрыто.")
                break
            (size,) = struct.unpack(">H", header)
            data = read_exact(reader, size)
            if data is None:
                log("Туннель->TUN", "Кадр оборван.")
                break
            tap.write(data)
        except (BrokenPipeError, OSError) as exc:
            log("Туннель->TUN", f"Канал закрыт: {type(exc).__name__}: {exc}")
            break
        except Exception as exc:  # noqa: BLE001 - поток не должен падать молча
            log("Туннель->TUN", f"{type(exc).__name__}: {exc}")
            break


def tap_to_pipe(tap: TapDevice, writer: BinaryIO, mtu: int = DEFAULT_MTU) -> None:
    """Переносит пакеты из TUN-адаптера в поток (tailcat)."""
    while not stop_event.is_set():
        try:
            frame = tap.read()
            if not frame:
                continue
            if len(frame) > mtu:
                continue
            writer.write(struct.pack(">H", len(frame)) + frame)
            writer.flush()
        except (BrokenPipeError, OSError) as exc:
            log("TUN->Туннель", f"Канал закрыт: {type(exc).__name__}: {exc}")
            break
        except Exception as exc:  # noqa: BLE001
            log("TUN->Туннель", f"{type(exc).__name__}: {exc}")
            break


def stderr_reader(stream: BinaryIO) -> None:
    """Печатает stderr дочернего процесса tailcat построчно."""
    try:
        for line in iter(stream.readline, b""):
            log("tailcat(stderr)", line.decode(errors="replace").rstrip())
    except Exception:  # noqa: BLE001
        pass


def create_tap(
    adapter: str,
    virtual_ip: str,
    netmask: str = NETMASK,
    mtu: int = DEFAULT_MTU,
) -> TapDevice:
    """Создаёт и настраивает TUN-адаптер.

    Raises:
        TunError: если адаптер нельзя создать (в том числе из-за прав)
            или настроить.
    """
    if not IS_WINDOWS and len(adapter) > IFNAMSIZ - 1:
        raise TunError(
            f"Имя интерфейса «{adapter}» длиннее {IFNAMSIZ - 1} символов — "
            "Linux такое имя не поддерживает. Укажите короче."
        )
    try:
        tap = TapDevice(name=adapter, mtu=mtu)
    except TapDeviceError as exc:
        raise TunError(f"Не удалось создать TUN-адаптер: {exc}") from exc
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror == 5 or exc.errno in (1, 13, 19):
            raise TunError(
                "Не удалось создать TUN-адаптер: нет прав администратора. "
                "Запустите приложение и подтвердите запрос UAC (Windows) "
                "или sudo (Linux)."
            ) from exc
        raise TunError(
            f"Не удалось создать TUN-адаптер: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        tap.ifconfig(ip=virtual_ip, netmask=netmask, mtu=mtu)
    except (TapDeviceError, OSError) as exc:
        try:
            tap.close()
        except Exception:  # noqa: BLE001
            pass
        raise TunError(
            f"Не удалось настроить TUN-адаптер {tap.name}: {exc}"
        ) from exc

    log("TUN", f"Интерфейс {tap.name}: {virtual_ip}/{netmask}, MTU {mtu}")
    ensure_subnet_route(tap.name, virtual_ip, netmask)
    return tap


# ---------------------------------------------------------------------------
# Надёжный чат по UDP
# ---------------------------------------------------------------------------


class ReliableChat:
    """UDP-чат с подтверждением доставки и повторной отправкой.

    Каждое сообщение получает уникальный id. Получатель отвечает ACK с этим id.
    Если ACK не пришёл за ``ack_timeout`` секунд, сообщение отправляется
    повторно, всего не больше ``ack_retries`` попыток.
    """

    def __init__(
        self,
        sock: socket.socket,
        peer_ip: str,
        chat_port: int,
        peer_label: str = "Собеседник",
        reliable: bool = True,
        ack_timeout: float = 1.5,
        ack_retries: int = 5,
        max_message: int = 900,
        on_message: Callable[[ChatMessage], None] | None = None,
        queue_messages: bool = True,
    ) -> None:
        self.sock = sock
        self.peer = (peer_ip, chat_port)
        self.peer_label = peer_label
        self.reliable = reliable
        self.ack_timeout = ack_timeout
        self.ack_retries = ack_retries
        self.max_message = max_message
        self.on_message = on_message
        self.queue_messages = queue_messages
        self.inbox: queue.Queue[ChatMessage] = queue.Queue()
        self.pending: dict[str, dict] = {}
        self.seen: deque[str] = deque(maxlen=4096)
        self.lock = threading.Lock()
        self.running = True

    # -- публичный интерфейс ------------------------------------------------

    def __enter__(self) -> "ReliableChat":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def start(self, console: bool = False) -> None:
        """Запускает фоновые потоки: приём, повторы и (опционально) ввод."""
        threading.Thread(target=self._receive_loop, daemon=True).start()
        threading.Thread(target=self._retry_loop, daemon=True).start()
        if console:
            threading.Thread(target=self._input_loop, daemon=True).start()

    def close(self) -> None:
        """Останавливает чат и закрывает сокет."""
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, text: str) -> bool:
        """Короткий псевдоним :meth:`send_message`."""
        return self.send_message(text)

    def send_message(self, text: str) -> bool:
        """Отправляет сообщение. False — если текст слишком длинный или не ушёл."""
        prepared = self._prepare(text)
        if prepared is None:
            return False
        msg_id, payload = prepared
        return self._deliver(msg_id, payload, text)

    def send_and_wait(self, text: str, timeout: float | None = None) -> bool:
        """Отправляет сообщение и ждёт подтверждения доставки (ACK).

        Возвращает True, если собеседник подтвердил получение.
        В режиме ``reliable=False`` подтверждений нет — вернётся True,
        если сообщение удалось отправить.
        """
        prepared = self._prepare(text)
        if prepared is None:
            return False
        msg_id, payload = prepared
        if not self._deliver(msg_id, payload, text):
            return False
        if not self.reliable:
            return True

        deadline = None if timeout is None else time.time() + timeout
        while True:
            with self.lock:
                if msg_id not in self.pending:
                    return True
            if deadline is not None and time.time() >= deadline:
                return False
            time.sleep(0.05)

    def receive(self, timeout: float | None = None) -> ChatMessage | None:
        """Возвращает следующее входящее сообщение или None по таймауту."""
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def messages(self) -> Iterator[ChatMessage]:
        """Итератор входящих сообщений, пока чат работает."""
        while self.running:
            message = self.receive(timeout=0.5)
            if message is not None:
                yield message

    def wait_pending(self, timeout: float | None = None) -> bool:
        """Ждёт подтверждения всех отправленных сообщений.

        Возвращает True, если очередь опустела, False — по таймауту.
        """
        deadline = None if timeout is None else time.time() + timeout
        while True:
            with self.lock:
                if not self.pending:
                    return True
            if deadline is not None and time.time() >= deadline:
                return False
            time.sleep(0.05)

    # -- внутреннее ---------------------------------------------------------

    def _prepare(self, text: str) -> tuple[str, bytes] | None:
        """Готовит сообщение к отправке. None — если текст слишком длинный."""
        encoded_len = len(text.encode("utf-8"))
        if encoded_len > self.max_message:
            log(
                "Чат",
                f"Слишком длинное сообщение: {encoded_len} байт, "
                f"максимум {self.max_message}.",
            )
            return None

        if self.reliable:
            msg_id = uuid.uuid4().hex[:16]
            payload = json.dumps(
                {"t": "msg", "id": msg_id, "text": text}, ensure_ascii=False
            ).encode("utf-8")
            with self.lock:
                self.pending[msg_id] = {
                    "payload": payload,
                    "attempt": 1,
                    "next": time.time() + self.ack_timeout,
                }
        else:
            msg_id = ""
            payload = text.encode("utf-8")
        return msg_id, payload

    def _deliver(self, msg_id: str, payload: bytes, text: str) -> bool:
        """Отправляет подготовленное сообщение по сети."""
        try:
            self._send_raw(payload)
        except OSError as exc:
            log("Чат", f"Не отправлено: {exc}")
            if self.reliable:
                with self.lock:
                    self.pending.pop(msg_id, None)
            return False
        log(f"Чат->{self.peer_label}", text)
        return True

    def wait_pending(self, timeout: float | None = None) -> bool:
        """Ждёт подтверждения всех отправленных сообщений.

        Возвращает True, если очередь опустела, False — по таймауту.
        """
        deadline = None if timeout is None else time.time() + timeout
        while True:
            with self.lock:
                if not self.pending:
                    return True
            if deadline is not None and time.time() >= deadline:
                return False
            time.sleep(0.05)

    # -- внутреннее ---------------------------------------------------------

    def _send_raw(self, payload: bytes, addr=None) -> None:
        self.sock.sendto(payload, addr or self.peer)

    def _input_loop(self) -> None:
        log(
            "Чат",
            f"Введите сообщение для {self.peer_label.lower()}а и нажмите Enter "
            "(Ctrl+C — выход).",
        )
        while self.running and not stop_event.is_set():
            try:
                line = input().strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            self.send_message(line)

    def _retry_loop(self) -> None:
        while self.running and not stop_event.is_set():
            time.sleep(0.2)
            now = time.time()
            expired = []
            with self.lock:
                for msg_id, item in list(self.pending.items()):
                    if item["next"] > now:
                        continue
                    if item["attempt"] >= self.ack_retries:
                        expired.append(msg_id)
                        continue
                    item["attempt"] += 1
                    item["next"] = now + self.ack_timeout
                    try:
                        self._send_raw(item["payload"])
                        log("Чат", f"Повторная отправка #{item['attempt']} (id {msg_id})")
                    except OSError as exc:
                        log("Чат", f"Повтор не удался: {exc}")
                for msg_id in expired:
                    self.pending.pop(msg_id, None)
            for msg_id in expired:
                log(
                    "Чат",
                    f"Сообщение не доставлено после {self.ack_retries} попыток "
                    f"(id {msg_id}).",
                )

    def _receive_loop(self) -> None:
        while self.running and not stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle(data, addr)

    def _handle(self, data: bytes, addr) -> None:
        msg_id = None
        is_ack = False
        text = None
        try:
            obj = json.loads(data.decode("utf-8"))
            if isinstance(obj, dict) and "t" in obj:
                msg_id = obj.get("id")
                if obj["t"] == "ack":
                    is_ack = True
                elif obj["t"] == "msg":
                    text = str(obj.get("text", ""))
                else:
                    return
            else:
                text = data.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, json.JSONDecodeError):
            text = data.decode("utf-8", errors="replace")

        if is_ack:
            with self.lock:
                item = self.pending.pop(msg_id, None)
            if item:
                log("Чат", f"Доставлено (id {msg_id}, попыток {item['attempt']}).")
            return

        if text is None:
            return

        if msg_id:
            with self.lock:
                duplicate = msg_id in self.seen
                if not duplicate:
                    self.seen.append(msg_id)
            if duplicate:
                # Повтор: наш прошлый ACK, видимо, потерялся — подтверждаем снова.
                self._send_ack(msg_id, addr)
                return
            self._send_ack(msg_id, addr)

        message = ChatMessage(
            text=text,
            sender=addr[0],
            message_id=msg_id or "",
            timestamp=time.time(),
            peer_label=self.peer_label,
        )

        if self.on_message is not None:
            try:
                self.on_message(message)
            except Exception as exc:  # noqa: BLE001 - сбой обработчика не должен ломать чат
                log("Чат", f"Ошибка в on_message: {type(exc).__name__}: {exc}")

        if self.queue_messages:
            self.inbox.put(message)

        log(f"Чат<-{self.peer_label}", f"{addr[0]}: {text}")

    def _send_ack(self, msg_id: str, addr) -> None:
        try:
            self._send_raw(json.dumps({"t": "ack", "id": msg_id}).encode("utf-8"), addr)
        except OSError:
            pass


def start_chat(config: ChatConfig) -> ReliableChat:
    """Создаёт UDP-сокет и запускает надёжный чат.

    Возвращает объект :class:`ReliableChat`, который можно использовать как
    контекстный менеджер::

        with start_chat(ChatConfig(peer_ip="10.0.0.1")) as chat:
            chat.send("привет")

    Raises:
        PortInUseError: если порт чата уже занят.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((config.bind_ip, config.chat_port))
    except OSError as exc:
        sock.close()
        raise PortInUseError(
            f"Не удалось занять порт чата {config.chat_port}: {exc}"
        ) from exc
    sock.settimeout(0.5)

    chat = ReliableChat(
        sock,
        config.peer_ip,
        config.chat_port,
        config.peer_label,
        config.reliable,
        config.ack_timeout,
        config.ack_retries,
        config.max_message,
        on_message=config.on_message,
        queue_messages=config.queue_messages,
    )
    chat.start(console=config.console)
    return chat


# ---------------------------------------------------------------------------
# Сервер и клиент туннеля
# ---------------------------------------------------------------------------


def resolve_token(config: ClientConfig, ask: bool = True) -> str:
    """Определяет адрес сервера: env, конфиг, файл, затем запрос в консоли."""
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        return token
    token = (config.token or "").strip()
    if token:
        return token
    token_file = Path(config.token_file)
    if token_file.exists():
        token = token_file.read_text(encoding="utf-8").strip()
        if token:
            return token
    if not ask:
        return ""
    return input("Токен: ").strip()


def _chat_config(config: TunnelConfig, peer_label: str) -> ChatConfig:
    return ChatConfig(
        chat_port=config.chat_port,
        peer_ip=config.peer_ip,
        peer_label=peer_label,
        reliable=config.reliable,
        ack_timeout=config.ack_timeout,
        ack_retries=config.ack_retries,
        max_message=config.max_message,
        console=config.console,
    )


def _bind_listener(port: int) -> socket.socket:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind(("127.0.0.1", port))
        listen_sock.listen(5)
    except OSError as exc:
        listen_sock.close()
        hint = (
            f"netstat -ano | findstr :{port}"
            if IS_WINDOWS
            else f"ss -tlnp | grep :{port}"
        )
        raise PortInUseError(
            f"Не удалось занять порт {port}: {exc}\n"
            f"Возможно, остался запущенный tailcat от прошлого раза. Проверьте: {hint}\n"
            f"Либо укажите другой порт: serve_port={port + 1}"
        ) from exc
    return listen_sock


def _accept_loop(listen_sock: socket.socket, tap: TapDevice, mtu: int) -> None:
    while not stop_event.is_set():
        try:
            conn, _addr = listen_sock.accept()
        except OSError:
            break
        log("Сервер", f"Tailcat подключился к порту {listen_sock.getsockname()[1]}")
        reader = conn.makefile("rb")
        writer = conn.makefile("wb")
        threading.Thread(target=pipe_to_tap, args=(reader, tap, mtu), daemon=True).start()
        threading.Thread(target=tap_to_pipe, args=(tap, writer, mtu), daemon=True).start()


def run_server(config: TunnelConfig) -> None:
    """Поднимает сервер: TUN, tailcat serve и чат.

    Блокирует поток до остановки (Ctrl+C или :data:`stop_event`).

    Raises:
        ByteLineError: при ошибке конфигурации, прав, IP, порта или tailcat.
    """
    config.validate()
    stop_event.clear()
    ensure_ip_available(
        config.virtual_ip, config.check_ip, config.ping_timeout, config.strict_ip
    )

    with create_tap(
        config.adapter, config.virtual_ip, config.netmask, config.mtu
    ) as tap:
        listen_sock = _bind_listener(config.serve_port)
        server: ServerProcess | None = None
        chat = None
        try:
            log(
                "Сервер",
                f"Слушаю 127.0.0.1:{config.serve_port} для подключений от tailcat",
            )
            log("Сервер", f"Запуск Tailcat serve на порту {config.serve_port}...")
            server = ServerProcess(
                serve=[config.serve_port],
                key="new",
                full_address=True,
                stderr=subprocess.PIPE,
            )
            try:
                token = server.start()
            except (BackendNotFound, ServerStartError, TimeoutError) as exc:
                raise TunnelError(
                    f"Не удалось запустить Tailcat: {type(exc).__name__}: {exc}"
                ) from exc

            token_path = Path(config.token_file)
            try:
                token_path.write_text(token + "\n", encoding="utf-8")
            except OSError as exc:
                raise TunnelError(
                    f"Не удалось сохранить токен в {token_path}: {exc}"
                ) from exc

            log("Сервер", f"Токен (сохранён в {token_path}):\n    {token}")
            log("Сервер", "Ожидание подключения клиента...")

            threading.Thread(
                target=stderr_reader, args=(server.process.stderr,), daemon=True
            ).start()
            threading.Thread(
                target=_accept_loop, args=(listen_sock, tap, config.mtu), daemon=True
            ).start()

            chat = start_chat(_chat_config(config, "Клиент"))

            try:
                while not stop_event.is_set():
                    if not server.is_running:
                        log("Сервер", "Tailcat завершился.")
                        break
                    time.sleep(0.5)
            except KeyboardInterrupt:
                log("Сервер", "Остановка по Ctrl+C.")
        finally:
            stop_event.set()
            if chat is not None:
                chat.close()
            try:
                listen_sock.close()
            except OSError:
                pass
            if server is not None:
                server.stop()


def run_client(config: ClientConfig) -> None:
    """Поднимает клиент: TUN, подключение к tailcat и чат.

    Блокирует поток до остановки (Ctrl+C или :data:`stop_event`).

    Raises:
        ByteLineError: при ошибке конфигурации, прав, IP, токена или tailcat.
    """
    config.validate()
    stop_event.clear()
    token = resolve_token(config)
    if not token:
        raise TunnelError("Токен не задан.")

    ensure_ip_available(
        config.virtual_ip, config.check_ip, config.ping_timeout, config.strict_ip
    )

    with create_tap(
        config.adapter, config.virtual_ip, config.netmask, config.mtu
    ) as tap:
        log("Туннель", f"Подключение к серверу (порт {config.serve_port})...")
        try:
            process = Client(token).connect(port=config.serve_port)
        except Exception as exc:  # noqa: BLE001 - tailkitty кидает разные типы
            raise TunnelError(
                f"Не удалось подключиться: {type(exc).__name__}: {exc}"
            ) from exc

        time.sleep(1.0)
        if process.poll() is not None:
            err = ""
            if process.stderr is not None:
                err = process.stderr.read().decode(errors="replace").strip()
            raise TunnelError(
                f"Tailcat завершился (код {process.returncode}): {err}"
            )

        log("Туннель", "Подключение установлено.")
        threading.Thread(
            target=stderr_reader, args=(process.stderr,), daemon=True
        ).start()

        threads = [
            threading.Thread(
                target=pipe_to_tap, args=(process.stdout, tap, config.mtu), daemon=True
            ),
            threading.Thread(
                target=tap_to_pipe, args=(tap, process.stdin, config.mtu), daemon=True
            ),
        ]
        for thread in threads:
            thread.start()

        chat = None
        try:
            chat = start_chat(_chat_config(config, "Сервер"))
            try:
                while not stop_event.is_set():
                    if process.poll() is not None:
                        log("Туннель", f"Tailcat завершился (код {process.returncode}).")
                        break
                    time.sleep(0.5)
            except KeyboardInterrupt:
                log("Туннель", "Остановка по Ctrl+C.")
        finally:
            stop_event.set()
            if chat is not None:
                chat.close()
            try:
                process.terminate()
            except Exception:  # noqa: BLE001
                pass
            for thread in threads:
                thread.join(timeout=3)


# ---------------------------------------------------------------------------
# Командная строка
# ---------------------------------------------------------------------------


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--adapter", default="pytap3", help="Имя TUN-адаптера")
    parser.add_argument("--virtual-ip", default=None, help="Виртуальный IP-адрес")
    parser.add_argument(
        "--netmask", default=NETMASK, help=f"Маска подсети (по умолчанию {NETMASK})"
    )
    parser.add_argument("--mtu", type=int, default=DEFAULT_MTU, help="MTU интерфейса")
    parser.add_argument(
        "--serve-port", type=int, default=DEFAULT_SERVE_PORT, help="Порт туннеля"
    )
    parser.add_argument(
        "--chat-port", type=int, default=DEFAULT_CHAT_PORT, help="Порт чата (UDP)"
    )
    parser.add_argument("--peer-ip", default=None, help="IP собеседника в туннеле")
    parser.add_argument(
        "--token-file", default=str(DEFAULT_TOKEN_FILE), help="Путь к файлу с токеном"
    )

    ip_group = parser.add_argument_group("проверка IP")
    ip_group.add_argument(
        "--check-ip",
        dest="check_ip",
        action="store_true",
        default=True,
        help="Проверять занятость IP пингом перед запуском (по умолчанию включено)",
    )
    ip_group.add_argument(
        "--no-check-ip",
        dest="check_ip",
        action="store_false",
        help="Не проверять занятость IP",
    )
    ip_group.add_argument(
        "--ping-timeout",
        type=float,
        default=1.0,
        help="Таймаут ping при проверке IP, секунды (по умолчанию 1.0)",
    )
    ip_group.add_argument(
        "--strict-ip",
        action="store_true",
        help="Прерывать запуск, если IP отвечает на ping (по умолчанию только предупреждение)",
    )

    chat_group = parser.add_argument_group("доставка сообщений")
    chat_group.add_argument(
        "--no-reliable",
        dest="reliable",
        action="store_false",
        default=True,
        help="Отключить подтверждения (ACK) и повторную отправку",
    )
    chat_group.add_argument(
        "--ack-timeout",
        type=float,
        default=1.5,
        help="Сколько ждать подтверждение доставки, секунды (по умолчанию 1.5)",
    )
    chat_group.add_argument(
        "--ack-retries",
        type=int,
        default=5,
        help="Сколько всего попыток отправки одного сообщения (по умолчанию 5)",
    )
    chat_group.add_argument(
        "--max-message",
        type=int,
        default=900,
        help="Максимальная длина сообщения в байтах (по умолчанию 900)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="byteline",
        description="ByteLine: туннель + чат в одном приложении (режимы server/client).",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(ELEVATED_FLAG, action="store_true", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server", help="Запустить сервер")
    add_common_args(server_parser)
    server_parser.set_defaults(
        adapter="pytap3-server", virtual_ip=DEFAULT_SERVER_IP, peer_ip=DEFAULT_CLIENT_IP
    )

    client_parser = subparsers.add_parser("client", help="Запустить клиент")
    add_common_args(client_parser)
    client_parser.add_argument("token", nargs="?", default="", help="Токен подключения")
    client_parser.add_argument(
        "--server", default="", help="Токен/адрес сервера (альтернатива позиционному)"
    )
    client_parser.set_defaults(
        adapter="pytap3-client", virtual_ip=DEFAULT_CLIENT_IP, peer_ip=DEFAULT_SERVER_IP
    )

    return parser


def config_from_args(args: argparse.Namespace) -> TunnelConfig:
    """Превращает результат разбора аргументов в конфигурацию."""
    common = dict(
        adapter=args.adapter,
        virtual_ip=args.virtual_ip,
        netmask=args.netmask,
        mtu=args.mtu,
        serve_port=args.serve_port,
        chat_port=args.chat_port,
        peer_ip=args.peer_ip,
        token_file=args.token_file,
        check_ip=args.check_ip,
        ping_timeout=args.ping_timeout,
        strict_ip=args.strict_ip,
        reliable=args.reliable,
        ack_timeout=args.ack_timeout,
        ack_retries=args.ack_retries,
        max_message=args.max_message,
        console=True,
    )
    if args.mode == "server":
        return ServerConfig(**common)
    return ClientConfig(token=(args.token or args.server or ""), **common)


def main(argv: list[str] | None = None) -> None:
    """Точка входа CLI. Возвращает управление только при штатной остановке."""
    raw = list(sys.argv[1:] if argv is None else argv)

    # Запуск без аргументов (например, двойным кликом по byteline.exe):
    # показываем справку и не даём окну закрыться мгновенно.
    if not raw:
        build_parser().print_help()
        if sys.stdin is not None and sys.stdin.isatty():
            try:
                input("\nНажмите Enter, чтобы закрыть окно...")
            except (EOFError, KeyboardInterrupt):
                pass
        return

    args = build_parser().parse_args(raw)
    config = config_from_args(args)
    failed = True
    try:
        config.validate()
        check_platform_support()
        require_admin(sys.argv[1:] if argv is None else argv)
        if args.mode == "server":
            run_server(config)
        else:
            run_client(config)
        failed = False
    except KeyboardInterrupt:
        stop_event.set()
        print("\nОстановлено пользователем.", flush=True)
        failed = False
    except ByteLineError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
    finally:
        # Окно, открытое через UAC/sudo, не должно закрываться мгновенно:
        # иначе сообщение об ошибке никто не увидит.
        if failed and (ELEVATED_FLAG in sys.argv or getattr(sys, "frozen", False)):
            if sys.stdin is not None and sys.stdin.isatty():
                try:
                    input("Нажмите Enter, чтобы закрыть окно...")
                except (EOFError, KeyboardInterrupt):
                    pass


if __name__ == "__main__":
    main()
