#!/usr/bin/python3
import fcntl
import struct
import os
import socket
import select
import threading
#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import dh
#from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import DH
from Crypto.Util.Padding import pad, unpad
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun_interface():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
    os.system("ip addr add 192.168.52.1/24 dev {}".format(ifname))
    os.system("ip link set dev {} up".format(ifname))
    return tun, ifname

def perform_dh_key_exchange(client_socket, server_private_key):

 # Send the public key to the client
    server_public_key = server_private_key.publickey()
    serialized_public_key = server_public_key.export_key(format='PEM')
    client_socket.send(serialized_public_key)

    # Receive the client's public key
    client_received_key = client_socket.recv(2048)
    client_public_key = DH.import_key(client_received_key)

    # Perform the key exchange and derive the shared key
    shared_key = server_private_key.exchange(client_public_key)
    return shared_key

def handle_client(client_socket, tun, server_private_key):
    shared_key = perform_dh_key_exchange(client_socket, server_private_key)
    
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()

    while True:
        data = client_socket.recv(2048)
        if not data:
            print("Connection closed by the client {}".format(client_socket.getpeername()))
            with lock:
                client_sockets.remove(client_socket)
            client_socket.close()
            break
        pkt = IP(data)
        print("From inside packet <==: {} --> {}".format(pkt.src, pkt.dst))
        os.write(tun, bytes(pkt))

def start_server():
    tun, ifname = create_tun_interface()

    server_private_key = dh.generate_private_key(key_size=2048, backend=default_backend())
    serverIP = "0.0.0.0"
    serverPort = 5555
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((serverIP, serverPort))
    sock.listen(5)

    client_sockets = []
    lock = threading.Lock()

    while True:
        readable, _, _ = select.select([sock, tun], [], [])
        for fd in readable:
            if fd is sock:
                client_sock, client_addr = sock.accept()
                print("Connection established with {}".format(client_addr))
                with lock:
                    client_sockets.append(client_sock)

                shared_key_thread = threading.Thread(target=handle_client, args=(client_sock, tun, server_private_key))
                shared_key_thread.start()

            elif fd is tun:
                packet = os.read(tun, 2048)
                with lock:
                    for client_socket in client_sockets:
                        client_socket.send(packet)

if __name__ == "__main__":
    start_server()
