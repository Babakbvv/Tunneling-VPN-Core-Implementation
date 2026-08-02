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




def handle_client(client_sock, client_addr, tun_fd):
    print(f"[+] Client connected from {client_addr}")
    client_virtual_ip = None
    
    try:
        while True:
            packet = receive_framed_packet(client_sock)
            if not packet:
                break
            
            src_ip_bytes = packet[12:16]
            if client_virtual_ip is None:
                client_virtual_ip = src_ip_bytes
                with clients_lock:
                    active_clients[client_virtual_ip] = client_sock
                    print(f"[i] Registered Virtual IP {socket.inet_ntoa(client_virtual_ip)} for {client_addr}")
                    print(f"[i] Active Clients Count: {len(active_clients)}")
            
            Maping_Nat_log(packet, client_addr)
            
            os.write(tun_fd, packet)
            
    except Exception as e:
        print(f"[-] Client error {client_addr}: {e}")
    finally:
        with clients_lock:
            if client_virtual_ip and client_virtual_ip in active_clients:
                del active_clients[client_virtual_ip]
        print(f"[-] Client disconnected: {client_addr}")
        print(f"[i] Active Clients Count: {len(active_clients)}")
        client_sock.close()




def tun_to_clients(tun_fd):
    while True:
        try:
            packet = os.read(tun_fd, 2048)
            if len(packet) >= 20:
                dst_ip_bytes = packet[16:20] 
                
                with clients_lock:
                    target_sock = active_clients.get(dst_ip_bytes)
                
                if target_sock:
                    send_framed_packet(target_sock, packet)
        except Exception as e:
            print(f"[-] Error routing from TUN: {e}")





def main():
    tun_fd = create_tun_interface("tun0")
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen(10)
    print(f"[*] VPN Server listening on {SERVER_IP}:{SERVER_PORT}")
    
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

    