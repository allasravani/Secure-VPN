# client.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import fcntl
import socket
import struct
import os
import select
import threading
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Diffie-Hellman parameters
p = 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291162945139
g = 2

def generate_private_key():
    return random.randint(2, p - 2)

def diffie_hellman_key_exchange(server_socket):
    x_client = generate_private_key()
    y_client = pow(g, x_client, p)
    server_socket.send(str(y_client).encode())
    server_public_key = int(server_socket.recv(2048).decode())
    shared_secret = pow(server_public_key, x_client, p)
    return shared_secret

def decrypt_shared_key(encrypted_shared_key):
    key = hashlib.sha256(b'SecretKey').digest()
    nonce = encrypted_shared_key[:16]
    tag = encrypted_shared_key[16:32]
    ciphertext = encrypted_shared_key[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_shared_key = int.from_bytes(cipher.decrypt_and_verify(ciphertext, tag), 'big')
    return decrypted_shared_key

def verify_shared_key(shared_key, decrypted_shared_key):
    return shared_key == decrypted_shared_key

def encrypt_shared_key_aes(shared_key):
    aes_key = hashlib.sha256(b'SecretAESKey').digest()
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(shared_key.to_bytes(32, 'big'))
    return nonce + tag + ciphertext

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.52.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

serverIP = "10.9.0.11"
serverPort = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((serverIP, serverPort))
print("Connected to server {}:{}".format(serverIP, serverPort))

shared_secret = diffie_hellman_key_exchange(sock)
print("Shared Secret:", shared_secret)

encrypted_shared_key = sock.recv(48)
decrypted_shared_key = decrypt_shared_key(encrypted_shared_key)
shared_key_verified = verify_shared_key(shared_secret, decrypted_shared_key)

if shared_key_verified:
    print("Shared Key Verified")

    def tun_and_server_communication():
        while True:
            ready, _, _ = select.select([sock, tun], [], [])
            for fd in ready:
                if fd is tun:
                    # Reading from TUN and sending to server
                    packet = os.read(tun, 2048)
                    sock.send(packet)
                elif fd is sock:
                    # Reading from server and writing to TUN
                    data = sock.recv(2048)
                    if not data:
                        print("Connection closed by the server")
                        exit()
                    pkt = IP(data)
                    print("From inside packet <==: {} --> {}".format(pkt.src, pkt.dst))
                    os.write(tun, bytes(pkt))

    # Create thread for handling TUN and server communication
    tun_and_server_thread = threading.Thread(target=tun_and_server_communication, daemon=True)

    # Start the thread
    tun_and_server_thread.start()

    # The main program will continue without waiting for the thread to finish
    while True:
        pass
else:
    print("Shared Key Verification Failed. Closing connection.")
    sock.close()

