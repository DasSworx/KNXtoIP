from scapy.packet import Packet
from scapy.sendrecv import send
import util.util_general as u
import KNX_Telegramme as t
import errors as e

"""
src, dst sind Strings mit Punktschreibweise
TTL ein int
checksumIsValid und isAck sind bools
data ist ein bytearray 
"""

def mapIncomingTraffic(surveiled_interface, receiver):
    print("Mapper Online")
    while True:
        packet = u.catch_traffic(surveiled_interface)
        print("NEW PACKET!")
        try:
            packetData = u.obtain_payload(packet)
            print("Payload found!")
        except e.NotAPacketError:
            print("No payload found in UDP-package")

        if 'packetData' in locals():
            send(convertKNXtoIP(packetData, receiver), verbose = 0)
        else:
            continue

def convertKNXtoIP(knx_package, receiver_network) -> Packet:
    if u.is_L_Data_Standard_Frame(knx_package):
        return t.L_Data_Standard_Frame(knx_package).asIP(receiver_network)
    elif u.is_L_Data_Extended_Frame(knx_package):
        return t.L_Data_Extended_Frame(knx_package).asIP(receiver_network)
    elif u.is_L_Poll_Data_Frame(knx_package):
        poll_telegram = t.L_Poll_Data_Frame(knx_package)
    elif u.isAck_Frame(knx_package):
        print("Ack was ignored")
    else:
        print("Illegal control field. Telegram type undefined")