from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from util import util_standard as u_std
from util import util_dataSecure as u_sec
from util import util_extended as u_ext



"""
src, dst sind Strings mit Punktschreibweise
TTL ein int
checksumIsValid und isAck sind bools
data ist ein bytearray 
"""

networkInterface = "0.0."
#TODO: add choice between UDP and TCP
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



def convertKNXtoIP(knx_package) -> Packet:
    if u_std.isL_DataFrame(knx_package):
        if u_std.isStandardFrame(knx_package):
            if u_sec.isSecureFrame():
                #TODO: DataSecurePackets
                print("decrypt Stuff")
            else:
                src = networkInterface + u_std.getSourceFromStandardFrame(knx_package)
                dst = networkInterface + u_std.getDestinationFromStandardFrame(knx_package)
                TTL = u_std.getHopCount(knx_package)
                checksumIsCorrect = u_std.checksumIsValid(knx_package)
                data = u_std.getDataFromStandardFrame(knx_package)
                return KNXasIP(src, dst, TTL, checksumIsCorrect, False, data)

        elif u_ext.isExtendedFrame(knx_package):
            print("Package is a Extended Frame")
            #TODO: Extended packets
            if u_sec.isSecureFrame():
                #TODO: DataSecureStuff
                print("decrypt stuff")
            else:
                src = u_ext.getSourceFromExtendedFrame(knx_package)
                dst = u_ext.getDestinationFromExtendedFrame(knx_package)
                TTL = u_ext.getHopCountFromExtendedFrame(knx_package)
                checksumIsCorrect = u_std.checksumIsValid(knx_package)
                data = u_ext.getDataFromExtenedFrame(knx_package)
                return KNXasIP(src, dst, TTL, checksumIsCorrect, False, data)
        else:
            print("Package could not be identified as standard or extended")

    elif u_std.isL_PollFrame(knx_package):
        #TODO: implement L_Poll
        print("Is L_Poll Frame")
    else:
        #TODO: implement ack
        print("Is Ack Frame")