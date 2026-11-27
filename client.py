import ctypes
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from pytap3 import TapDevice, TapDeviceError
from tailkitty import Client

VIRTUAL_IP = "10.0.0.2"
NETMASK = "255.255.255.0"
MTU = 1200
ADAPTER_NAME = "pytap3-client"
TOKEN_PATH = Path(__file__).with_name("token.txt")

SERVE_PORT = 9000
CHAT_PORT = 59999
PEER_IP = "10.0.0.1"

stop_event = threading.Event()


def log(tag: str, message: str) -> None:
    print(f"[{tag}] {message}", flush=True)


def require_admin() -> None:
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        return
    if not is_admin:
        sys.exit("Нужны права администратора: перезапустите терминал от имени администратора.")


def read_token() -> str:
    token = os.environ.get("TUNNEL_TOKEN", "").strip()
    if token:
        return token
    if len(sys.argv) > 1:
        return sys.argv[1].strip()
    if TOKEN_PATH.exists():
        return TOKEN_PATH.read_text(encoding="utf-8").strip()
    return input("Токен: ").strip()


def ensure_subnet_route() -> None:
    result = subprocess.run(
        [
            "netsh", "interface", "ipv4", "add", "route", "10.0.0.0/24",
            f"interface={ADAPTER_NAME}", "nexthop=0.0.0.0",
            "metric=1", "store=active",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log("TUN", "Маршрут уже существует (это нормально).")


def read_exact(stream, size: int):
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def pipe_to_tap(reader, tap: TapDevice) -> None:
    while not stop_event.is_set():
        try:
            header = read_exact(reader, 2)
            if header is None:
                log("Туннель->TUN", "Соединение закрыто сервером.")
                break
            (size,) = struct.unpack(">H", header)
            data = read_exact(reader, size)
            if data is None:
                log("Туннель->TUN", "Кадр оборван.")
                break
            tap.write(data)
        except (BrokenPipeError, OSError) as e:
            log("Туннель->TUN", f"Канал закрыт: {type(e).__name__}: {e}")
            break
        except Exception as e:
            log("Туннель->TUN", f"{type(e).__name__}: {e}")
            break


def tap_to_pipe(tap: TapDevice, writer) -> None:
    while not stop_event.is_set():
        try:
            frame = tap.read()
            if not frame:
                continue
            if len(frame) > MTU:
                continue
            writer.write(struct.pack(">H", len(frame)) + frame)
            writer.flush()
        except (BrokenPipeError, OSError) as e:
            log("TUN->Туннель", f"Канал закрыт: {type(e).__name__}: {e}")
            break
        except Exception as e:
            log("TUN->Туннель", f"{type(e).__name__}: {e}")
            break


def stderr_reader(stream) -> None:
    try:
        for line in iter(stream.readline, b""):
            log("tailcat(stderr)", line.decode(errors="replace").rstrip())
    except Exception:
        pass


def chat_listener(sock: socket.socket) -> None:
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        log("Чат<-Сервер", f"{addr[0]}: {data.decode(errors='replace')}")


def chat_sender(sock: socket.socket) -> None:
    log("Чат", "Введите сообщение для сервера и нажмите Enter (Ctrl+C — выход).")
    while not stop_event.is_set():
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        try:
            sock.sendto(line.encode("utf-8"), (PEER_IP, CHAT_PORT))
            log("Чат->Сервер", line)
        except OSError as e:
            log("Чат", f"Не отправлено: {e}")


def main() -> None:
    require_admin()

    token = read_token()
    if not token:
        sys.exit("Токен не задан.")

    try:
        tap = TapDevice(name=ADAPTER_NAME, mtu=MTU)
    except TapDeviceError as e:
        sys.exit(f"Не удалось создать TUN-адаптер: {e}")

    with tap:
        tap.ifconfig(ip=VIRTUAL_IP, netmask=NETMASK, mtu=MTU)
        log("TUN", f"Интерфейс {ADAPTER_NAME}: {VIRTUAL_IP}/{NETMASK}, MTU {MTU}")
        ensure_subnet_route()

        log("Туннель", f"Подключение к серверу (порт {SERVE_PORT})...")
        try:
            process = Client(token).connect(port=SERVE_PORT)
        except Exception as e:
            log("Туннель", f"Не удалось подключиться: {type(e).__name__}: {e}")
            sys.exit(1)

        time.sleep(1.0)
        if process.poll() is not None:
            err = process.stderr.read().decode(errors="replace").strip() if process.stderr else ""
            sys.exit(f"Tailcat завершился (код {process.returncode}): {err}")

        log("Туннель", "Подключение установлено.")
        threading.Thread(target=stderr_reader, args=(process.stderr,), daemon=True).start()

        threads = [
            threading.Thread(target=pipe_to_tap, args=(process.stdout, tap), daemon=True),
            threading.Thread(target=tap_to_pipe, args=(tap, process.stdin), daemon=True),
        ]
        for t in threads:
            t.start()

        chat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        chat_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            chat_sock.bind(("0.0.0.0", CHAT_PORT))
        except OSError as e:
            log("Чат", f"Не удалось занять порт {CHAT_PORT}: {e}")
        chat_sock.settimeout(0.5)
        threading.Thread(target=chat_listener, args=(chat_sock,), daemon=True).start()
        threading.Thread(target=chat_sender, args=(chat_sock,), daemon=True).start()

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
            chat_sock.close()
            try:
                process.terminate()
            except Exception:
                pass
            for t in threads:
                t.join(timeout=3)


if __name__ == "__main__":
    main()