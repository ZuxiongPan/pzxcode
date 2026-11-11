
#!/usr/bin/env python3
import socket
import time
import traceback

SOCKET_PATH = "/tmp/uart_fpga.sock"

SOF = 0x02
EOF = 0x03

MAX_PAYLOAD = 250


def dump_data(tag, data):
    """打印原始数据，HEX 和 ASCII 两种形式。"""
    hex_data = " ".join(f"{b:02X}" for b in data)
    ascii_data = "".join(
        chr(b) if 32 <= b <= 126 else "."
        for b in data
    )

    print(f"{tag} len={len(data)}")
    print(f"    HEX  : {hex_data}")
    print(f"    ASCII: {ascii_data}")


def make_frame(payload):
    """组装 SOF + LEN + PAYLOAD + EOF。"""
    if not payload or len(payload) > MAX_PAYLOAD:
        raise ValueError(f"Invalid payload length: {len(payload)}")

    return bytes([SOF, len(payload)]) + payload + bytes([EOF])


def parse_frames(rx_buffer):
    """
    从接收缓冲区提取完整帧。
    返回 [(frame, payload), ...]
    """
    frames = []

    while True:
        # 寻找帧头
        try:
            sof_pos = rx_buffer.index(SOF)
        except ValueError:
            rx_buffer.clear()
            break

        # 丢弃帧头之前的无效数据
        if sof_pos > 0:
            garbage = bytes(rx_buffer[:sof_pos])
            print("[!] Discarding garbage data:")
            dump_data("GARBAGE", garbage)
            del rx_buffer[:sof_pos]

        # 至少需要 SOF + LEN
        if len(rx_buffer) < 2:
            break

        length = rx_buffer[1]

        # 长度异常，丢弃当前帧头，继续寻找
        if length == 0 or length > MAX_PAYLOAD:
            print(f"[!] Invalid payload length: {length}")
            del rx_buffer[0]
            continue

        total_len = 1 + 1 + length + 1

        # 数据还没有接收完整
        if len(rx_buffer) < total_len:
            break

        # 检查帧尾
        if rx_buffer[total_len - 1] != EOF:
            print("[!] Invalid EOF, resync...")
            dump_data("BAD FRAME", bytes(rx_buffer[:total_len]))
            del rx_buffer[0]
            continue

        frame = bytes(rx_buffer[:total_len])
        payload = frame[2:2 + length]

        del rx_buffer[:total_len]

        frames.append((frame, payload))

    return frames


def handle_command(payload):
    """处理 FPGA 命令并生成响应。"""
    try:
        cmd = payload.decode("ascii")
    except UnicodeDecodeError:
        cmd = ""

    print(f"[<] Command: {cmd!r}")

    if cmd == "VERSION":
        response = b"PZX-FPGA-V2.0"

    elif cmd == "TIME":
        response = f"TS:{int(time.time())}".encode("ascii")

    else:
        response = b"UNKNOWN_CMD"

    return response


def main():
    print("[*] Starting UART FPGA Simulator...")
    print(f"[*] Socket path: {SOCKET_PATH}")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        print("[*] Connecting to QEMU...")
        sock.connect(SOCKET_PATH)

        print("[+] Connected to QEMU successfully!")
        print("[*] Waiting for UART data...")

        # 超时用于周期性检查退出，不代表通信失败
        sock.settimeout(1.0)

        rx_buffer = bytearray()

        while True:
            try:
                chunk = sock.recv(1024)

                if not chunk:
                    print("[!] QEMU disconnected the socket.")
                    break

                # 第一步：无条件打印原始数据
                print("\n========== UART RX ==========")
                dump_data("[RX RAW]", chunk)

                rx_buffer.extend(chunk)

                # 第二步：尝试解析协议帧
                frames = parse_frames(rx_buffer)

                for frame, payload in frames:
                    print("[+] Valid frame received:")
                    dump_data("[RX FRAME]", frame)
                    dump_data("[RX PAYLOAD]", payload)

                    # 第三步：处理命令
                    response = handle_command(payload)

                    # 第四步：构造并发送回复
                    response_frame = make_frame(response)

                    print("[>] Sending response:")
                    dump_data("[TX FRAME]", response_frame)

                    sock.sendall(response_frame)

                    print("[+] Response sent successfully.")

            except socket.timeout:
                continue

            except KeyboardInterrupt:
                print("\n[*] User requested exit.")
                break

            except Exception:
                print("[!] Communication error:")
                traceback.print_exc()
                break

    except FileNotFoundError:
        print(f"[!] Socket does not exist: {SOCKET_PATH}")
        print("[!] Start QEMU first.")

    except ConnectionRefusedError:
        print("[!] QEMU socket exists but connection was refused.")

    except Exception:
        print("[!] Connection error:")
        traceback.print_exc()

    finally:
        sock.close()
        print("[*] FPGA simulator stopped.")


if __name__ == "__main__":
    main()

