from scapy.packet import Packet, Raw
from scapy.layers.inet import IP
from errors import NotAPacketError
import os

def stripDownToIP(pkt):
    strippedPkt = IP(pkt.bytes)
    strippedPkt.show()

def catch_traffic(interface) -> Packet:
    pkt = IP(os.read(interface, 4096))
    return pkt

def obtain_payload(package) -> bytearray:
    if isinstance(package, Packet):
        data = package[Raw].load
        return data
    else:
        raise NotAPacketError

def is_L_Data_Standard_Frame(telegram):
    first_byte = telegram[0]
    if (first_byte >> 7) == 1 and ((first_byte >> 6) & 1) == 0 and ((first_byte >> 4) & 1) == 1:
        return True
    else:
        return False

def is_L_Data_Extended_Frame(telegram):
    first_byte = telegram[0]
    if (first_byte >> 7) == 0 and ((first_byte >> 6) & 1) == 0 and ((first_byte >> 4) & 1) == 1:
        return True
    else:
        return False

def is_L_Poll_Data_Frame(telegram):
    first_byte = telegram[0]
    if ((first_byte >> 6) & 1) == 1 and ((first_byte >> 4) & 1) == 1:
        return True
    else:
        return False

def isAck_Frame(telegram):
    first_byte = telegram[0]
    if ((first_byte >> 4) & 1) == 0:
        return True
    else:
        return False

def calculateChecksum(telegram):
    checksum = 0
    for byte in telegram[:-1]:
        checksum ^= byte
    checksum ^= 0xff
    return checksum