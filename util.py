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

def isL_DataFrame(knx_frame):
    first_byte = knx_frame[0]
    if ((first_byte >> 4) & 1) == 0:
        print("knx_frame is ack")
        return false
    elif ((first_byte >> 6) & 1) == 1:
        print("knx_frame is L_Poll frame")
        return false
    else:
        return true

def isL_PollFrame(knx_frame):
    first_byte = knx_frame[0]
    if ((first_byte >> 4) & 1) == 0:
        print("knx_frame is ack")
        return false
    elif ((first_byte >> 6) & 1) == 0:
        print("knx_frame is L_Data frame")
        return false
    else:
        return true

def isAckFrame(knx_frame):
    first_byte = knx_frame[0]
    if ((first_byte >> 4) & 1) == 0:
        return true
    else:
        return false

def isStandartFrame(L_Data_Frame) -> bool:
    firstByte = L_Data_Frame[0]
    if((firstByte >> 7) & 1) == 1: #Test if first bit is 0 for standart package
        return true
    else:
        return false

def isExtendedFrame(L_DataFrame):
    firstByte = L_DataFrame[0]
    if ((firstByte >> 7) & 1) == 0:
        return true
    else:
        return false

def getSourceFromStandardFrame(data) -> str:
    secondByte = data[1]
    thirdByte = data[2]
    source = str(secondByte) + "." + str(thirdByte)
    return source

def getDestinationFromStandardFrame(data) -> str:
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

def frameIsSecure(data) -> bool:
    #TODO: implement actuall check
    return true

def getHopCount(data) -> int:
    return data[5] >> 4

def getDataFromStandardFrame(knx_frame):
    return knx_frame[6:-1]

def getDataFromExtenedFrame(knx_frame):
    return knx_frame[7:-1]

def getSourceFromExtendedFrame(knx_frame):
    third_byte = knx_frame[2]
    fourth_byte = knx_frame[3]
    source = str(third_byte) + "." + str(fourth_byte)
    return source

def getDestinationFromExtendedFrame(knx_frame):
    fifth_byte = knx_frame[4]
    sixth_byte = knx_frame[5]
    destination = str(fifth_byte) + "." + str(sixth_byte)
    return destination

#the extended frame knows two address types: 0 for point to point communication and 1 for all multicast shenanigans
def getAddressTypeFromExtendedFrame(knx_frame) -> int:
    extendedControlField = knx_frame[1]
    return (extendedControlField >> 7) & 1

def getHopCountFromExtendedFrame(knx_frame) -> int:
    extendedControlField = knx_frame[1]
    return (extendedControlField >> 4) & 0x07

def calculateChecksum(data) -> bytearray:
    checksum = 0
    for byte in data[:-1]:
        checksum ^= byte
        checksum ^= 0xff
    return checksum

def obtainChecksum(data) -> bytearray:
    return data[-1]

def checksumIsValid(data) -> bool:
    if calculateChecksum(data) == obtainChecksum(data):
        return True
    else:
        return False