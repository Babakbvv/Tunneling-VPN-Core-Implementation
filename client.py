import os
import fcntl
import struct
import socket
import threading
from cryptography.fernet import Fernet

SERVER_IP = "127.0.0.1"  
SERVER_PORT = 8080       


SECRET_KEY = b'G5yS3xZ2aK_9WpM4q1v8L0oRtU6yI7eX3mN8bV1cA2d='
cipher = Fernet(SECRET_KEY)


def create_tun_interface(dev_name="tun0"):
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", dev_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    
    print(f"[+] TUN interface '{dev_name}' created successfully.")
    return tun_fd



def send_framed_packet(sock, payload):
    encrypted_payload = cipher.encrypt(payload)
    length_prefix = struct.pack("!I", len(encrypted_payload))
    sock.sendall(length_prefix + encrypted_payload)



def recv_exact(sock, n_bytes):
    data = b""
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data





def receive_framed_packet(sock):
    header = recv_exact(sock, 4)
    if not header:
        return None
    packet_len = struct.unpack("!I", header)[0]
    encrypted_payload = recv_exact(sock, packet_len)
    if not encrypted_payload:
        return None
    return cipher.decrypt(encrypted_payload)