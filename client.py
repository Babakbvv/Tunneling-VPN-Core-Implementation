import os
import fcntl
import struct
import socket
import threading
import sys
from cryptography.fernet import Fernet

SERVER_IP = "10.0.2.15"  # آی‌پی سرور را تنظیم کن
SERVER_PORT = 8080

SECRET_KEY = b'G5yS3xZ2aK_9WpM4q1v8L0oRtU6yI7eX3mN8bV1cA2d='
cipher = Fernet(SECRET_KEY)

# کدهای ثابت نوع پیام
MSG_AUTH_REQ = 1
MSG_AUTH_OK = 2
MSG_AUTH_FAIL = 3
MSG_DATA = 4

def create_tun_interface(dev_name="tun0"):
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", dev_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    
    print(f"[+] TUN interface '{dev_name}' created successfully.")
    return tun_fd

def recv_exact(sock, n_bytes):
    data = b""
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data

# ارسال پیام با هدر ۵ بایتی (۱ بایت type + ۴ بایت length)
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

def authenticate(sock):
    username = input("Username: ")
    password = input("Password: ")
    
    auth_data = f"{username}:{password}".encode('utf-8')
    encrypted_auth = cipher.encrypt(auth_data)
    
    send_msg(sock, MSG_AUTH_REQ, encrypted_auth)
    
    msg_type, payload = recv_msg(sock)
    if msg_type == MSG_AUTH_OK:
        assigned_vip = payload.decode('utf-8')
        print(f"[+] Authentication Successful! Assigned Virtual IP: {assigned_vip}")
        return True
    else:
        reason = payload.decode('utf-8') if payload else "Unknown error"
        print(f"[-] Authentication Failed: {reason}")
        return False

def server_to_tun(tun_fd, sock):
    while True:
        try:
            msg_type, payload = recv_msg(sock)
            if msg_type is None:
                print("[-] Server disconnected.")
                break
            
            # فقط بسته‌های داده شبکه پردازش می‌شوند
            if msg_type == MSG_DATA and payload:
                decrypted_packet = cipher.decrypt(payload)
                os.write(tun_fd, decrypted_packet)
        except Exception as e:
            print(f"[-] Error in server_to_tun: {e}")
            break

def tun_to_server(tun_fd, sock):
    while True:
        try:
            raw_packet = os.read(tun_fd, 2048)
            if raw_packet:
                print(f"[DEBUG CLIENT] Read {len(raw_packet)} bytes from TUN, sending to server...")
                encrypted_payload = cipher.encrypt(raw_packet)
                send_msg(sock, MSG_DATA, encrypted_payload)
        except Exception as e:
            print(f"[-] Error in tun_to_server: {e}")
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] Connecting to VPN Server at {SERVER_IP}:{SERVER_PORT}...")
    
    try:
        sock.connect((SERVER_IP, SERVER_PORT))
        print("[+] Connected to VPN Server!")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # ۱. فرآیند احراز هویت پیش از ساخت tun0
    if not authenticate(sock):
        sock.close()
        return

    # ۲. ساخت تونل پس از تایید موفقیت‌آمیز ورود
    tun_fd = create_tun_interface("tun0")

    t1 = threading.Thread(target=tun_to_server, args=(tun_fd, sock), daemon=True)
    t2 = threading.Thread(target=server_to_tun, args=(tun_fd, sock), daemon=True)

    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[*] Disconnecting...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()