from time import sleep
import errors as e
import os
import fcntl
import struct
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, send

from util import util_general as u


def sendingMessage():
    knxTestMessage = bytes(
        [0b10110000, 0b00100011, 0b00000101, 0b00010000, 0b00000001, 0b00000010, 0b00000000, 0b00000001, 0b10100010])

    test_package = IP(src="42.42.0.21", dst="42.42.0.15") / UDP(dport = 12345) / Raw(load=knxTestMessage)
    send(test_package)

def analysePackages():
    while True:
        new_package = u.catch_traffic()
        new_package.show()
        package_data = u.obtain_payload(new_package)
        package_sender = u.getSourceFromStandardFrame(package_data)
        print(f"source is: {package_sender}")

def sniffer():
    print("sniffer online")
    while True:
        packet = u.catch_traffic()
        try:
            packetData = u.obtain_payload(packet)
        except e.NotAPacketError:
            print("No payload found in UDP-package")

        if packetData in globals():

            #standart message:
            if u.isStandardFrame(packetData):
                print("Standard Frame")
            #extended frame:
            else:
                print("Non-Standard Frame")
        else:
            continue

def spammer():
    print("Spammer online")
    while True:
        print("Sending message")
        sendingMessage
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
    while True:
        os.read(interface, 2048)