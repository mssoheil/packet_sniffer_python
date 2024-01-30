import socket
from scapy.all import *
from scapy.layers.l2 import Ether

def main():
    snifferSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    interface = "eth0"
    snifferSocket.bind((interface, 0))

    try:
        while True:
            rawData, addr = snifferSocket.recvfrom(65535)
            packet = Ether(rawData)
            print(packet.summary())
            print(addr)
            
    except KeyboardInterrupt:
        snifferSocket.close()


if __name__ == "__main__":
    main()