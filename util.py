from importlib.resources import Package
from scapy import *
from scapy.interfaces import show_interfaces
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw, Packet
from scapy.sendrecv import send, sendp, sniff
from scapy.config import conf
from errors import *

true = True
false = False

def catch_traffic() -> Packet:
    pkt = sniff(iface = "lo", count = 1)
    return pkt[0]


def obtain_payload(package) -> bytearray:
    if isinstance(package, Packet):
        data = package[Raw].load
        return data
    else:
        raise NotAPacketError

def isStandartFrame(data) -> bool:
    firstByte = data[0]
    if((firstByte >> 6) & 1) == 0: #Test if second bit is 0 for standart package
        return true
    else:
        return false

def isValidPackage(data) -> bool:
    firstByte = data[0]
    if (((firstByte >> 7) & 1) == 1):  # Test if first bit is 1 (as it needs to be for all KNX packages)
        return true
    else:
        raise InvalidKNXPacketError

def getSource(data) -> str:
    secondByte = data[1]
    thirdByte = data[2]
    source = str(secondByte) + "." + str(thirdByte)
    return source

def getDestination(data) -> str:
    fourthByte = data[3]
    fifthByte = data[4]
    destination = str(fourthByte) + "." + str(fifthByte)
    return destination

def messageIsAck(data) -> bool:
    firstByte = data[0]
    if (firstByte & 1) == 1:
        return true
    else:
        return false

def calculateChecksum(data) -> bytearray:
    checksum = 0
    for byte in data[:-1]:
        checksum ^= byte
    return checksum

def obtainChecksum(data) -> bytearray:
    return data[-1]

def frameIsSecure(data) -> bool:
    #TODO: Code actuall check
    return true

def getHopCount(data) -> int:
    return data[5] >> 4

def getDataFromStandardPackage(data):
    return data[6:-1]

def checksumIsValid(data) -> bool:
    if calculateChecksum(data) == obtainChecksum(data):
        return True
    else:
        return False