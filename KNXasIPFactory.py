from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
import util as u
import errors as err
from util import false, true

"""
src, dst sind Strings mit Punktschreibweise
TTL ein int
checksumIsValid und isAck sind bools
data ist ein bytearray 
"""

networkInterface = "0.0."

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
    if u.isL_DataFrame(knx_package):
        if u.isStandartFrame(knx_package):
            if u.isSecureFrame():
                #TODO: DataSecurePackets
                print("decrypt Stuff")
            else:
                src = networkInterface + u.getSource(knx_package)
                dst = networkInterface + u.getDestination(knx_package)
                TTL = u.getHopCount(knx_package)
                checksumIsCorrect = u.checksumIsValid(knx_package)
                data = u.getDataFromStandardPackage(knx_package)
                return KNXasIP(src, dst, TTL, checksumIsCorrect, false, data)

        else:
            print("Package is a Extended Frame")
            #TODO: Extended packets
    else:
        #TODO: check for L_POLL and ack
        print("Wasnt a L_Data_Frame")