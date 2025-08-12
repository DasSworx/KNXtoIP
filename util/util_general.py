from scapy.packet import Packet, Raw
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
import Bytes as B
from errors import NotAPacketError
import os

def stripDownToIP(pkt):
    strippedPkt = IP(pkt.bytes)
    strippedPkt.show()

def catch_traffic(interface) -> Packet:
    pkt = IP(os.read(interface, 4096))
    return pkt[0]

def obtain_payload(package) -> bytearray:
    if isinstance(package, Packet):
        data = package[Raw].load
        return data
    else:
        raise NotAPacketError

def isL_DataFrame(knx_frame):
    first_byte = B.Byte(knx_frame[0])
    if first_byte.getBit4() == 0:
        print("knx_frame is ack")
        return False
    elif first_byte.getBit6() == 1:
        print("knx_frame is L_Poll frame")
        return False
    else:
        return True

def isL_PollFrame(knx_frame):
    first_byte = B.Byte(knx_frame[0])
    if first_byte.getBit4() == 0:
        print("knx_frame is ack")
        return False
    elif first_byte.getBit6() == 0:
        print("knx_frame is L_Data frame")
        return False
    else:
        return True

def isAck_Frame(knx_frame):
    first_byte = B.Byte(knx_frame[0])
    if first_byte.getBit4() == 0:
        print("knx_frame is ack")
        return True
    else:
        print("knx_frame is not an ack")
        return False
