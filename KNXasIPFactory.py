from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

"""
src, dst sind Strings mit Punktschreibweise
TTL ein int
checksumIsValid und isAck sind bools
data ist ein bytearray 
"""
def KNXasIP(src, dst, TTL, checksumIsValid, isAck, data) -> Packet:
    if isAck:
        knxpacket = IP(src = src, dst = dst, ttl = TTL) / TCP(flags = "A") / data
    else:
        knxpacket = IP(src = src, dst = dst, ttl = TTL) / TCP() / data

    if checksumIsValid:
        return knxpacket
    else:
        knxpacket[IP].chksum = 0xFFFF
        return knxpacket