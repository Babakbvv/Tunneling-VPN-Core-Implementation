import os
import fcntl
import struct
import socket
import threading
import time
from cryptography.fernet import Fernet
import database  # ماژول دیتابیس

SERVER_IP = "0.0.0.0"
SERVER_PORT = 8080
SECRET_KEY = b'G5yS3xZ2aK_9WpM4q1v8L0oRtU6yI7eX3mN8bV1cA2d='
cipher = Fernet(SECRET_KEY)

# کدهای ثابت نوع پیام
MSG_AUTH_REQ = 1
MSG_AUTH_OK = 2
MSG_AUTH_FAIL = 3
MSG_DATA = 4

clients_lock = threading.Lock()
active_clients = {}      # mapping: virtual_ip_bytes -> client_sock
port_mapping_table = {}  # NAT Logging Table

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

# ارسال پیام با هدر ۵ بایتی (۱ بایت نوع + ۴ بایت طول)
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

def Maping_Nat_log(packet, client_addr):
    """استخراج هدر IP/TCP/UDP و ثبت لاگ جدول NAT"""
    if len(packet) < 20:
        return
    
    version = packet[0]
    ihl = (version & 0xF) * 4 
    protocol = packet[9]           
    
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    
    if protocol == 6 or protocol == 17: # TCP یا UDP
        if len(packet) >= ihl + 4:
            src_port = struct.unpack("!H", packet[ihl:ihl+2])[0]
            dst_port = struct.unpack("!H", packet[ihl+2:ihl+4])[0]
            
            mapping_key = (src_ip, src_port, dst_ip, dst_port)
            if mapping_key not in port_mapping_table:
                port_mapping_table[mapping_key] = client_addr
                proto_name = "TCP" if protocol == 6 else "UDP"
                print(f"[NAT LOG] {proto_name} | Client {client_addr} -> {src_ip}:{src_port} to {dst_ip}:{dst_port}")

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

        # دریافت محدودیت سرعت اختصاصی این کاربر از دیتابیس
        user_max_bytes_per_sec = database.get_user_speed_limit(authenticated_user)

        # ۳. دریافت بسته‌های داده شبکه
        while True:
            # بررسی سهمیه پیش از پردازش بسته جدید
            has_quota, status_msg = database.check_user_quota(authenticated_user)
            if not has_quota:
                print(f"[!] Disconnecting user '{authenticated_user}': {status_msg}")
                send_msg(client_sock, MSG_AUTH_FAIL, status_msg.encode('utf-8'))
                break

            msg_type, payload = recv_msg(client_sock)
            if msg_type is None:
                break
                
            if msg_type == MSG_DATA and payload:
                packet = cipher.decrypt(payload)
                pkt_len = len(packet)
                if pkt_len < 20: 
                    continue
                
                src_ip_bytes = packet[12:16]
                if src_ip_bytes == b'\x00\x00\x00\x00': 
                    continue

                # ثبت IP مجازی کلاینت برای مسیر بازگشتی
                if client_virtual_ip is None:
                    client_virtual_ip = src_ip_bytes
                    with clients_lock:
                        active_clients[client_virtual_ip] = client_sock
                    print(f"[i] Registered Virtual IP {socket.inet_ntoa(client_virtual_ip)} for '{username}' ({client_addr})")
                    print(f"[i] Active Clients Count: {len(active_clients)}")

                # ثبت لاگ NAT
                Maping_Nat_log(packet, client_addr)

                # اعمال محدودیت سرعت اختصاصی کاربر
                if user_max_bytes_per_sec > 0:
                    sleep_time = pkt_len / user_max_bytes_per_sec
                    if sleep_time > 0:
                        time.sleep(sleep_time)

                # ثبت آمار حجم مصرفی در دیتابیس
                database.update_usage(authenticated_user, upload_add=pkt_len)

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
        print(f"[i] Active Clients Count: {len(active_clients)}")
        client_sock.close()

def tun_to_clients(tun_fd):
    """خوانش پاسخ‌ها از tun0 و هدایت آن‌ها به سوکت کلاینت مربوطه"""
    while True:
        try:
            packet = os.read(tun_fd, 2048)
            if len(packet) >= 20:
                dst_ip_bytes = packet[16:20] # IP مقصد از هدر پکت
                
                with clients_lock:
                    target_sock = active_clients.get(dst_ip_bytes)
                
                if target_sock:
                    # ارسال پکت داده بازگشتی با تگ MSG_DATA و رمزنگاری
                    encrypted_payload = cipher.encrypt(packet)
                    send_msg(target_sock, MSG_DATA, encrypted_payload)
        except Exception as e:
            print(f"[-] Error routing from TUN: {e}")

def main():
    database.init_db()
    tun_fd = create_tun_interface("tun0")
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen(10)
    print(f"[*] VPN Server listening on {SERVER_IP}:{SERVER_PORT}")
    
    # نخ مجزا برای مسیریابی بازگشتی از اینترنت به کلاینت‌ها
    threading.Thread(target=tun_to_clients, args=(tun_fd,), daemon=True).start()
    
    try:
        while True:
            client_sock, client_addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(client_sock, client_addr, tun_fd), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()