import os
import fcntl
import struct
import socket
import threading
from cryptography.fernet import Fernet

SERVER_IP = "0.0.0.0"  
SERVER_PORT = 8080
SECRET_KEY = b'G5yS3xZ2aK_9WpM4q1v8L0oRtU6yI7eX3mN8bV1cA2d='
cipher = Fernet(SECRET_KEY)

clients_lock = threading.Lock()
active_clients = {}   
port_mapping_table = {}    

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

def receive_framed_packet(sock):
    header = recv_exact(sock, 4)
    if not header: return None
    packet_len = struct.unpack("!I", header)[0]
    encrypted_payload = recv_exact(sock, packet_len)
    if not encrypted_payload: return None
    return cipher.decrypt(encrypted_payload)

def send_framed_packet(sock, payload):
    encrypted_payload = cipher.encrypt(payload)
    length_prefix = struct.pack("!I", len(encrypted_payload))
    sock.sendall(length_prefix + encrypted_payload)

def Maping_Nat_log(packet, client_addr):

    if len(packet) < 20:
        return
    
    version = packet[0]
    ihl = (version & 0xF) * 4 
    protocol = packet[9]           
    
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    
    if protocol == 6 or protocol == 17:
        if len(packet) >= ihl + 4:
            src_port = struct.unpack("!H", packet[ihl:ihl+2])[0]
            dst_port = struct.unpack("!H", packet[ihl+2:ihl+4])[0]
            
            mapping_key = (src_ip, src_port, dst_ip, dst_port)
            if mapping_key not in port_mapping_table:
                port_mapping_table[mapping_key] = client_addr
                proto_name = "TCP" if protocol == 6 else "UDP"
                print(f"[NAT LOG] {proto_name} | Client {client_addr} -> {src_ip}:{src_port} to {dst_ip}:{dst_port}")