from time import sleep
import errors as e
import os
import fcntl
import struct
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, send

from util import util_general as u

knx_Standard_Data_Frame = bytes(
        [0b10110000, 0b00100011, 0b00000101, 0b00010000, 0b00000001, 0b00010010, 0b00000000, 0b00000001, 0b00000000, 0b01101011])

knx_Extended_Data_Frame = bytes(
    [0b00010000, 0b01010000, 0b11101111, 0b00001111, 0b00111010, 0b01010101, 0b00010000, 0b01000001, 
     0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 
     0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000,
     0b01100001]
)


def sendingMessage():
    

    test_package = IP(src="42.42.0.21", dst="42.42.0.15") / UDP(dport = 12345) / Raw(load=knx_Extended_Data_Frame)
    send(test_package, verbose = 0)

def analysePackages():
    while True:
        new_package = u.catch_traffic()
        new_package.show()
        package_data = u.obtain_payload(new_package)
        package_sender = u.getSourceFromStandardFrame(package_data)
        print(f"source is: {package_sender}")

def sniffer(interface):
    print("sniffer online")
    while True:
        
        packet = u.catch_traffic(interface)
        print("KNX PACKET AS IP: ")
        packet.show()
        

def spammer():
    print("Spammer online")
    seq_nr = 0
    while True:
        print("Sending message" + str(seq_nr))
        sendingMessage()
        seq_nr += 1
        sleep(5)

IFF_TUN   = 0x0001   
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

def getFileDescribtor(if_name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", if_name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd

def receivePackets(interface):
    print("Receiver started")
    while True:
        os.read(interface, 4096)
        
        