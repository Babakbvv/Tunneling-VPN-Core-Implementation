import os
import fcntl
import struct
import socket
import threading
from cryptography.fernet import Fernet
import database  # اتصال به فایل database.py

BIND_IP = "0.0.0.0"
BIND_PORT = 8080

SECRET_KEY = b'G5yS3xZ2aK_9WpM4q1v8L0oRtU6yI7eX3mN8bV1cA2d='
cipher = Fernet(SECRET_KEY)

# کدهای ثابت نوع پیام (دقیقاً هماهنگ با کلاینت)
MSG_AUTH_REQ = 1
MSG_AUTH_OK = 2
MSG_AUTH_FAIL = 3
MSG_DATA = 4

active_clients = {}
clients_lock = threading.Lock()

def create_tun_interface(dev_name="tun0"):
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", dev_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    
    print(f"[+] Server TUN interface '{dev_name}' created successfully.")
    return tun_fd

def recv_exact(sock, n_bytes):
    data = b""
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data

# ارسال پیام با هدر ۵ بایتی
def send_msg(sock, msg_type, payload=b""):
    header = struct.pack("!BI", msg_type, len(payload))
    sock.sendall(header + payload)

# دریافت پیام با هدر ۵ بایتی
def recv_msg(sock):
    header = recv_exact(sock, 5)
    if not header:
        return None, None
    msg_type, payload_len = struct.unpack("!BI", header)
    payload = recv_exact(sock, payload_len)
    return msg_type, payload

def handle_client(client_sock, client_addr, tun_fd):
    print(f"[+] Client connected from {client_addr}")
    authenticated_user = None
    client_virtual_ip = None
    
    try:
        # ۱. مرحله Handshake و دریافت اطلاعات ورود
        msg_type, payload = recv_msg(client_sock)
        if msg_type != MSG_AUTH_REQ or not payload:
            send_msg(client_sock, MSG_AUTH_FAIL, b"Invalid auth request format")
            client_sock.close()
            return
            
        decrypted_auth = cipher.decrypt(payload).decode('utf-8')
        username, password = decrypted_auth.split(":", 1)
        
        # ۲. اعتبارسنجی در دیتابیس (AAA)
        is_valid, reason = database.authenticate_user(username, password)
        if not is_valid:
            print(f"[-] Auth failed for user '{username}': {reason}")
            send_msg(client_sock, MSG_AUTH_FAIL, reason.encode('utf-8'))
            client_sock.close()
            return
            
        print(f"[+] User '{username}' authenticated successfully!")
        send_msg(client_sock, MSG_AUTH_OK, b"OK")
        authenticated_user = username

        # ۳. دریافت بسته‌های داده شبکه
        while True:
            msg_type, payload = recv_msg(client_sock)
            if msg_type is None:
                break
                
            if msg_type == MSG_DATA and payload:
                packet = cipher.decrypt(payload)
                if len(packet) < 20: 
                    continue
                
                src_ip_bytes = packet[12:16]
                if src_ip_bytes == b'\x00\x00\x00\x00': 
                    continue

                if client_virtual_ip is None:
                    client_virtual_ip = src_ip_bytes
                    with clients_lock:
                        active_clients[client_virtual_ip] = client_sock
                    print(f"[i] Registered Virtual IP {socket.inet_ntoa(client_virtual_ip)} for '{username}'")

                # ثبت آمار حجم مصرفی کلاینت در دیتابیس (Upload)
                database.update_usage(authenticated_user, upload_add=len(packet))

                try:
                    os.write(tun_fd, packet)
                except OSError:
                    pass

    except Exception as e:
        print(f"[-] Error handling client {client_addr}: {e}")
    finally:
        with clients_lock:
            if client_virtual_ip and client_virtual_ip in active_clients:
                del active_clients[client_virtual_ip]
        print(f"[-] Client disconnected: {client_addr} (User: {authenticated_user})")
        client_sock.close()

def main():
    # ۱. راه‌اندازی دیتابیس SQLite
    database.init_db()
    
    # ۲. ساخت تونل شبکه سرور
    tun_fd = create_tun_interface("tun0")
    
    # ۳. راه‌اندازی سوکت گوش‌به‌زنگ
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BIND_IP, BIND_PORT))
    server_sock.listen(5)
    
    print(f"[*] VPN Server listening on {BIND_IP}:{BIND_PORT}...")
    
    while True:
        client_sock, client_addr = server_sock.accept()
        t = threading.Thread(target=handle_client, args=(client_sock, client_addr, tun_fd), daemon=True)
        t.start()

if __name__ == "__main__":
    main()