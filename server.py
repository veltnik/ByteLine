import ctypes
import socket
import struct
import subprocess
import sys
import threading
import time

from pytap3 import TapDevice, TapDeviceError
from tailkitty import BackendNotFound, ServerProcess, ServerStartError

VIRTUAL_IP = "10.0.0.1"
NETMASK = "255.255.255.0"
MTU = 1200
ADAPTER_NAME = "pytap3-server"
TOKEN_PATH = "token.txt"

SERVE_PORT = 9000
CHAT_PORT = 59999
PEER_IP = "10.0.0.2"

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
                log("Туннель->TUN", "Соединение закрыто.")
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
        log("Чат<-Клиент", f"{addr[0]}: {data.decode(errors='replace')}")


def chat_sender(sock: socket.socket) -> None:
    log("Чат", "Введите сообщение для клиента и нажмите Enter (Ctrl+C — выход).")
    while not stop_event.is_set():
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        try:
            sock.sendto(line.encode("utf-8"), (PEER_IP, CHAT_PORT))
            log("Чат->Клиент", line)
        except OSError as e:
            log("Чат", f"Не отправлено: {e}")


def accept_loop(listen_sock: socket.socket, tap: TapDevice) -> None:
    while not stop_event.is_set():
        try:
            conn, addr = listen_sock.accept()
        except OSError:
            break
        log("Сервер", f"Tailcat подключился к порту {SERVE_PORT}")
        reader = conn.makefile("rb")
        writer = conn.makefile("wb")
        threading.Thread(target=pipe_to_tap, args=(reader, tap), daemon=True).start()
        threading.Thread(target=tap_to_pipe, args=(tap, writer), daemon=True).start()


def main() -> None:
    require_admin()

    try:
        tap = TapDevice(name=ADAPTER_NAME, mtu=MTU)
    except TapDeviceError as e:
        sys.exit(f"Не удалось создать TUN-адаптер: {e}")

    with tap:
        tap.ifconfig(ip=VIRTUAL_IP, netmask=NETMASK, mtu=MTU)
        log("TUN", f"Интерфейс {ADAPTER_NAME}: {VIRTUAL_IP}/{NETMASK}, MTU {MTU}")
        ensure_subnet_route()

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock.bind(("127.0.0.1", SERVE_PORT))
            listen_sock.listen(5)
        except OSError as e:
            sys.exit(f"Не удалось занять порт {SERVE_PORT}: {e}")
        log("Сервер", f"Слушаю 127.0.0.1:{SERVE_PORT} для подключений от tailcat")

        log("Сервер", f"Запуск Tailcat serve на порту {SERVE_PORT}...")
        server = ServerProcess(
            serve=[SERVE_PORT],
            key="new",
            full_address=True,
            stderr=subprocess.PIPE,
        )
        try:
            token = server.start()
        except (BackendNotFound, ServerStartError, TimeoutError) as e:
            sys.exit(f"Не удалось запустить Tailcat: {type(e).__name__}: {e}")

        with open(TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(token + "\n")

        log("Сервер", f"Токен (сохранён в {TOKEN_PATH}):\n    {token}")
        log("Сервер", "Ожидание подключения клиента...")

        threading.Thread(target=stderr_reader, args=(server.process.stderr,), daemon=True).start()
        threading.Thread(target=accept_loop, args=(listen_sock, tap), daemon=True).start()

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
                if not server.is_running:
                    log("Сервер", "Tailcat завершился.")
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            log("Сервер", "Остановка по Ctrl+C.")
        finally:
            stop_event.set()
            chat_sock.close()
            try:
                listen_sock.close()
            except Exception:
                pass
            server.stop()


if __name__ == "__main__":
    main()