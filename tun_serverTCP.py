#!/usr/bin/python3
import fcntl
import struct
import os
import time
import socket
import select
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.52.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

serverIP = "0.0.0.0"  # Listen on all available interfaces
serverPort = 5555
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((serverIP, serverPort))
sock.listen(1)

# Accept a TCP connection
client_sock, client_addr = sock.accept()
#sock.accept()
print("Connection established with {}".format(client_addr))

ip="zero"
port=0
while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([client_sock, tun], [], [])
    for fd in ready:
        if fd is client_sock:
            data = client_sock.recv(2048)
            if not data:
                print("Connection closed by the client")
                break
            pkt = IP(data)
            print("From inside packet <==: {} --> {}".format(pkt.src, pkt.dst))
           #print("From outside socket: source ip {}, source port {}".format(ip, port))
            os.write(tun, bytes(pkt))
        if fd is tun:
            packet = os.read(tun, 2048)
            client_sock.send(packet)
            #if port == 0:
             #   print("This VPN needs to start from the client outside the private network\n")
              #  break
            #else:
             #   client_sock.send(packet)

client_sock.close()
sock.close()
os.close(tun)

