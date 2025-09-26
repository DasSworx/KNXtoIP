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
        packet = u.catch_eth(surveiled_interface)

        print("NEW PACKET!")
        try:
            cEMI_frame = u.obtain_payload(packet)
            print(cEMI_frame)
            additional_information_len = cEMI_frame[7]
            print("additional Length:")
            print(additional_information_len)
            knx_frame = cEMI_frame[7+additional_information_len:]

            print("Payload found!")
        except e.NotAPacketError:
            print("No payload found in UDP-package")

        if 'knx_frame' in locals():
            send(convertKNXtoIP(knx_frame, receiver), verbose = 0)
            print("packet send!")
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