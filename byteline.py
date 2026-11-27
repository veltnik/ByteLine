"""ByteLine: клиент и сервер в одном файле (Windows и Linux).

При запуске без прав администратора скрипт сам перезапускается:
на Windows — через UAC, на Linux/macOS — через sudo.

Примеры запуска:
    python byteline.py server
    python byteline.py server --serve-port 9000 --chat-port 59999
    python byteline.py client <token>
    python byteline.py client --token <token> --adapter pytap3-client
"""

import argparse
import ctypes
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from pytap3 import TapDevice, TapDeviceError
from tailkitty import BackendNotFound, Client, ServerProcess, ServerStartError

IS_WINDOWS = os.name == "nt"
IFNAMSIZ = 16  # Linux: имя интерфейса вместе с завершающим NUL

NETMASK = "255.255.255.0"
DEFAULT_MTU = 1200
DEFAULT_SERVE_PORT = 9000
DEFAULT_CHAT_PORT = 59999
DEFAULT_SERVER_IP = "10.0.0.1"
DEFAULT_CLIENT_IP = "10.0.0.2"
TOKEN_PATH = Path(__file__).with_name("token.txt")

stop_event = threading.Event()


def log(tag: str, message: str) -> None:
    print(f"[{tag}] {message}", flush=True)


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except AttributeError:
            return True
    return os.geteuid() == 0


def require_admin() -> None:
    if not is_admin():
        relaunch_as_admin()


def relaunch_as_admin() -> None:
    if "--elevated-attempt" in sys.argv:
        if IS_WINDOWS:
            hint = "запустите терминал от имени администратора."
        else:
            hint = "запустите от root: sudo python3 byteline.py ..."
        sys.exit(f"Не удалось получить права администратора: {hint}")

    script = os.path.abspath(sys.argv[0])

    if IS_WINDOWS:
        params = subprocess.list2cmdline(["--elevated-attempt", *sys.argv[1:]])
        log("Права", "Запрашиваю права администратора (UAC)...")
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', os.getcwd(), 1
        )
        if rc <= 32:
            sys.exit("Не удалось перезапустить с правами администратора (UAC отклонён?).")
        sys.exit(0)

    log("Права", "Запрашиваю права root через sudo...")
    cmd = ["sudo", "-E", sys.executable, script, "--elevated-attempt", *sys.argv[1:]]
    try:
        os.execvpe("sudo", cmd, os.environ.copy())
    except OSError as e:
        sys.exit(f"Не удалось перезапустить через sudo: {e}")


def check_platform_support() -> None:
    """Проверяет, что TUN вообще доступен на этой системе."""
    if IS_WINDOWS:
        return
    if not os.path.exists("/dev/net/tun"):
        sys.exit(
            "Нет /dev/net/tun. В WSL1 TUN недоступен — переведите дистрибутив на WSL2 "
            "(wsl --set-version <distro> 2) или используйте обычный Linux. "
            "На обычном Linux: sudo mknod /dev/net/tun c 10 200 && sudo chmod 666 /dev/net/tun"
        )
    if shutil.which("ifconfig") is None:
        sys.exit("Не найдена утилита ifconfig (нужна pytap3): sudo apt install net-tools")
    if shutil.which("ip") is None:
        sys.exit("Не найдена утилита ip: sudo apt install iproute2")


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


def pipe_to_tap(reader, tap: TapDevice, mtu: int) -> None:
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


def tap_to_pipe(tap: TapDevice, writer, mtu: int) -> None:
    while not stop_event.is_set():
        try:
            frame = tap.read()
            if not frame:
                continue
            if len(frame) > mtu:
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


def chat_listener(sock: socket.socket, peer_label: str) -> None:
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        log(f"Чат<-{peer_label}", f"{addr[0]}: {data.decode(errors='replace')}")


def chat_sender(sock: socket.socket, peer_ip: str, chat_port: int, peer_label: str) -> None:
    log("Чат", f"Введите сообщение для {peer_label.lower()}а и нажмите Enter (Ctrl+C — выход).")
    while not stop_event.is_set():
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        try:
            sock.sendto(line.encode("utf-8"), (peer_ip, chat_port))
            log(f"Чат->{peer_label}", line)
        except OSError as e:
            log("Чат", f"Не отправлено: {e}")


def start_chat(chat_port: int, peer_ip: str, peer_label: str) -> socket.socket:
    chat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    chat_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        chat_sock.bind(("0.0.0.0", chat_port))
    except OSError as e:
        log("Чат", f"Не удалось занять порт {chat_port}: {e}")
    chat_sock.settimeout(0.5)
    threading.Thread(target=chat_listener, args=(chat_sock, peer_label), daemon=True).start()
    threading.Thread(
        target=chat_sender, args=(chat_sock, peer_ip, chat_port, peer_label), daemon=True
    ).start()
    return chat_sock


def ensure_subnet_route(adapter: str, virtual_ip: str) -> None:
    subnet = virtual_ip.rsplit(".", 1)[0] + ".0/24"
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


def create_tap(adapter: str, virtual_ip: str, mtu: int) -> TapDevice:
    if not IS_WINDOWS and len(adapter) > IFNAMSIZ - 1:
        sys.exit(
            f"Имя интерфейса «{adapter}» длиннее {IFNAMSIZ - 1} символов — "
            "Linux такое имя не поддерживает. Укажите короче через --adapter."
        )
    try:
        tap = TapDevice(name=adapter, mtu=mtu)
    except TapDeviceError as e:
        sys.exit(f"Не удалось создать TUN-адаптер: {e}")
    tap.ifconfig(ip=virtual_ip, netmask=NETMASK, mtu=mtu)
    log("TUN", f"Интерфейс {tap.name}: {virtual_ip}/{NETMASK}, MTU {mtu}")
    ensure_subnet_route(tap.name, virtual_ip)
    return tap


def read_client_token(args: argparse.Namespace) -> str:
    token = os.environ.get("TUNNEL_TOKEN", "").strip()
    if token:
        return token
    token = (args.token or "").strip()
    if token:
        return token
    token_file = Path(args.token_file)
    if token_file.exists():
        token = token_file.read_text(encoding="utf-8").strip()
        if token:
            return token
    return input("Токен: ").strip()


def run_server(args: argparse.Namespace) -> None:
    with create_tap(args.adapter, args.virtual_ip, args.mtu) as tap:
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock.bind(("127.0.0.1", args.serve_port))
            listen_sock.listen(5)
        except OSError as e:
            sys.exit(f"Не удалось занять порт {args.serve_port}: {e}")
        log("Сервер", f"Слушаю 127.0.0.1:{args.serve_port} для подключений от tailcat")

        log("Сервер", f"Запуск Tailcat serve на порту {args.serve_port}...")
        server = ServerProcess(
            serve=[args.serve_port],
            key="new",
            full_address=True,
            stderr=subprocess.PIPE,
        )
        try:
            token = server.start()
        except (BackendNotFound, ServerStartError, TimeoutError) as e:
            sys.exit(f"Не удалось запустить Tailcat: {type(e).__name__}: {e}")

        token_path = Path(args.token_file)
        with open(token_path, "w", encoding="utf-8") as f:
            f.write(token + "\n")

        log("Сервер", f"Токен (сохранён в {token_path}):\n    {token}")
        log("Сервер", "Ожидание подключения клиента...")

        threading.Thread(
            target=stderr_reader, args=(server.process.stderr,), daemon=True
        ).start()
        threading.Thread(
            target=accept_loop, args=(listen_sock, tap, args.mtu), daemon=True
        ).start()

        chat_sock = start_chat(args.chat_port, args.peer_ip, "Клиент")

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


def accept_loop(listen_sock: socket.socket, tap: TapDevice, mtu: int) -> None:
    while not stop_event.is_set():
        try:
            conn, addr = listen_sock.accept()
        except OSError:
            break
        log("Сервер", f"Tailcat подключился к порту {listen_sock.getsockname()[1]}")
        reader = conn.makefile("rb")
        writer = conn.makefile("wb")
        threading.Thread(target=pipe_to_tap, args=(reader, tap, mtu), daemon=True).start()
        threading.Thread(target=tap_to_pipe, args=(tap, writer, mtu), daemon=True).start()


def run_client(args: argparse.Namespace) -> None:
    token = read_client_token(args)
    if not token:
        sys.exit("Токен не задан.")

    with create_tap(args.adapter, args.virtual_ip, args.mtu) as tap:
        log("Туннель", f"Подключение к серверу (порт {args.serve_port})...")
        try:
            process = Client(token).connect(port=args.serve_port)
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
            threading.Thread(
                target=pipe_to_tap, args=(process.stdout, tap, args.mtu), daemon=True
            ),
            threading.Thread(
                target=tap_to_pipe, args=(tap, process.stdin, args.mtu), daemon=True
            ),
        ]
        for t in threads:
            t.start()

        chat_sock = start_chat(args.chat_port, args.peer_ip, "Сервер")

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


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--adapter", default="pytap3", help="Имя TUN-адаптера")
    parser.add_argument("--virtual-ip", default=None, help="Виртуальный IP-адрес")
    parser.add_argument("--mtu", type=int, default=DEFAULT_MTU, help="MTU интерфейса")
    parser.add_argument(
        "--serve-port", type=int, default=DEFAULT_SERVE_PORT, help="Порт туннеля"
    )
    parser.add_argument(
        "--chat-port", type=int, default=DEFAULT_CHAT_PORT, help="Порт чата (UDP)"
    )
    parser.add_argument("--peer-ip", default=None, help="IP собеседника в туннеле")
    parser.add_argument(
        "--token-file", default=str(TOKEN_PATH), help="Путь к файлу с токеном"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ByteLine: туннель + чат в одном файле (режимы server/client)."
    )
    parser.add_argument("--elevated-attempt", action="store_true", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server", help="Запустить сервер")
    add_common_args(server_parser)
    server_parser.set_defaults(
        adapter="pytap3-server", virtual_ip=DEFAULT_SERVER_IP, peer_ip=DEFAULT_CLIENT_IP
    )

    client_parser = subparsers.add_parser("client", help="Запустить клиент")
    add_common_args(client_parser)
    client_parser.add_argument("token", nargs="?", default="", help="Токен подключения")
    client_parser.set_defaults(
        adapter="pytap3-client", virtual_ip=DEFAULT_CLIENT_IP, peer_ip=DEFAULT_SERVER_IP
    )

    return parser


def main() -> None:
    args = build_parser().parse_args()
    check_platform_support()
    require_admin()
    if args.mode == "server":
        run_server(args)
    else:
        run_client(args)


if __name__ == "__main__":
    main()
