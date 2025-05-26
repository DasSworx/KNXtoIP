from importlib.resources import Package
from scapy import *
from scapy.interfaces import show_interfaces
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw, Packet
from scapy.sendrecv import send, sendp, sniff
from scapy.config import conf
from errors import *
import Bytes as B


def isAckFrame(knx_frame):
    first_byte = B.Byte(knx_frame[0])
    if first_byte.getBit4() == 0:
        return True
    else:
        return False

def isStandardFrame(L_Data_Frame) -> bool:
    firstByte = B.Byte(L_Data_Frame[0])
    if firstByte.getBit7() == 1: #Test if first bit is 0 for standart package
        return True
    else:
        return False

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
    firstByte = B.Byte(data[0])
    if firstByte.getBit0() == 1:
        return True
    else:
        return False

def getHopCountFromStandard(data) -> int:
    return data[5] >> 4

def getTPCIControllFlagFromStandard(knx_frame):
    seventh_byte = B.Byte(knx_frame[6])
    return seventh_byte.getBit7()

def getNumberedFromTPCIStandard(knx_frame):
    seventh_byte = B.Byte(knx_frame[6])
    return seventh_byte.getBit6()

def getSeqNrFromStandard(knx_frame) -> int:
    seventh_byte = knx_frame[6]
    return (seventh_byte >> 2) & 0x0f

def getDataFromStandardFrame(knx_frame):
    return knx_frame[6:-1]

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