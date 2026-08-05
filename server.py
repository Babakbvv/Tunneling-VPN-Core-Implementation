import os
import fcntl
import struct
import socket
import threading
import time
from cryptography.fernet import Fernet
from dns import message as dns_message

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
dns_cache = {} 
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


def parse_dns_domain(dns_payload):
    try:
        # تبدیل بایت‌های خام به شیء قابل فهم DNS
        msg = dns_message.from_wire(dns_payload)
        if msg.question:
            # گرفتن اولین سوال مطرح شده در بسته DNS (نام دامنه)
            domain = msg.question[0].name.to_text().rstrip('.')
            return domain
    except Exception:
        pass
    return "-"




def get_domain_from_ip(ip_str):
    """گرفتن آدرس IP و تحویل دادن اسم دامنه به سادگی"""
    try:
        # تنظیم یک تایم‌اوت کوتاه (مثلا نیم ثانیه) که سرور معطل نشه
        socket.setdefaulttimeout(0.5)
        # استعلام مستقیم اسم دامنه از روی IP
        domain_name, _, _ = socket.gethostbyaddr(ip_str)
        return domain_name
    except Exception:
        # اگر دامنه‌ای برای آن IP پیدا نشد
        return "-"


def Maping_Nat_log(packet, client_addr, username):
    """استخراج هدر IP و تمام پروتکل‌ها (TCP/UDP/ICMP) و ثبت لاگ"""
    if len(packet) < 20:
        return
    
    version_ihl = packet[0]
    ihl = (version_ihl & 0xF) * 4  # طول هدر IP
    protocol = packet[9]           # کد پروتکل
    
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    
    # تشخیص نوع پروتکل و استخراج پورت/اطلاعات
    src_port = 0
    dst_port = 0
    domain_name = "-"

    if protocol == 6:
        proto_name = "TCP"
    elif protocol == 17:
        proto_name = "UDP"
    elif protocol == 1:
        proto_name = "ICMP"
    else:
        proto_name = f"PROTO_{protocol}"

    # ۱. پردازش پورت‌ها برای TCP و UDP
    if protocol in (6, 17) and len(packet) >= ihl + 4:
        src_port = struct.unpack("!H", packet[ihl:ihl+2])[0]
        dst_port = struct.unpack("!H", packet[ihl+2:ihl+4])[0]
        
        # استخراج دامنه در صورت وجود درخواست DNS روی پورت 53 UDP
        if protocol == 17 and dst_port == 53 and len(packet) > ihl + 8:
            udp_payload = packet[ihl+8:]
            domain_name = parse_dns_domain(udp_payload)

    # ۲. پردازش ICMP (مثل Ping)
    elif protocol == 1 and len(packet) >= ihl + 2:
        icmp_type = packet[ihl]
        icmp_code = packet[ihl+1]
        dst_port = icmp_type  # ذخیره Type پکت پینگ به جای پورت
        domain_name = f"ICMP Type:{icmp_type} Code:{icmp_code}"

    # ثبت در دیتابیس
    try:
        database.log_traffic(username, src_ip, dst_ip, dst_port, domain_name, proto_name)
    except Exception as e:
        print(f"[-] Database Logging Error: {e}")

    # ثبت در جدول NAT حافظه سرور
    mapping_key = (src_ip, src_port, dst_ip, dst_port, proto_name)
    if mapping_key not in port_mapping_table:
        port_mapping_table[mapping_key] = client_addr
        print(f"[NAT LOG] {proto_name} | Client: {username} ({client_addr}) | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Info: {domain_name}")






def tun_to_clients(tun_fd):
    while True:
        try:
            packet = os.read(tun_fd, 2048)
            if len(packet) >= 20:
                dst_ip_bytes = packet[16:20]
                
                with clients_lock:
                    target_info = active_clients.get(dst_ip_bytes)
                
                if target_info:
                    # ثبت حجم دانلود (Download Accounting)
                    database.update_usage(target_info["username"], download_add=len(packet))
                    
                    encrypted_payload = cipher.encrypt(packet)
                    send_msg(target_info["sock"], MSG_DATA, encrypted_payload)
                else:
                    print(f"unkonkn :{list(dst_ip_bytes)}")
        except Exception as e:
            
            print("ip route wrong")


def kick_user_by_username(username):
    """قطع اتصال اجباری کاربر (Client Disconnection) از طریق پنل وب"""
    with clients_lock:
        vips_to_remove = []
        for vip, info in active_clients.items():
            if info["username"] == username:
                try:
                    info["sock"].close()
                except Exception:
                    pass
                vips_to_remove.append(vip)
        for vip in vips_to_remove:
            del active_clients[vip]
    print(f"[!] Forcefully kicked user '{username}' from Admin Panel.")


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
        
        # اختصاص آدرس آی‌پی مجازی ثابت/پویا به کلاینت (مثلاً 10.8.0.2)
        assigned_vip_str = "10.8.0.2" 
        client_virtual_ip = socket.inet_aton(assigned_vip_str)

        with clients_lock:
            # ذخیره سوکت و نام‌کاربری با کلید IP مجازی (بایت)
            active_clients[client_virtual_ip] = {
                "sock": client_sock,
                "username": username
            }
        
        print(f"[i] Registered Virtual IP {assigned_vip_str} for '{username}' ({client_addr})")
        print(f"[i] Active Clients Count: {len(active_clients)}")

        # ارسال تایید ورود به همراه آی‌پی مجازی اختصاص یافته به کلاینت
        send_msg(client_sock, MSG_AUTH_OK, assigned_vip_str.encode('utf-8'))
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
              #  print(f"[DEBUG SERVER] Received packet with len {len(packet)} from client!")
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


                # اعمال محدودیت سرعت اختصاصی کاربر
                if user_max_bytes_per_sec > 0:
                    sleep_time = pkt_len / user_max_bytes_per_sec
                    if sleep_time > 0:
                        time.sleep(sleep_time)

                # ثبت آمار حجم مصرفی در دیتابیس
                database.update_usage(authenticated_user, upload_add=pkt_len)

                try:
                    Maping_Nat_log(packet, client_addr ,username)
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
