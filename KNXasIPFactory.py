from scapy.packet import Packet
from scapy.sendrecv import send
import util.util_general as u
import KNX_Telegramme as t
import errors as e
import os

"""
src, dst sind Strings mit Punktschreibweise
TTL ein int
checksumIsValid und isAck sind bools
data ist ein bytearray 
"""

def mapIncomingTrafficFromEth(surveiled_interface, receiver):
    print("Eth-Mapper Online")
    while True:
        packet = u.catch_eth(surveiled_interface)
        print("NEW PACKET!")
        try:
            if not u.udp_uses_knx_port:
                print("UDP does not use KNX-Port")
                continue
            knx_ip_cEMI_frame = u.obtain_payload(packet)
            if knx_ip_cEMI_frame is None:
                print("Skipped empty UDP message")
                continue
            u.print_bytes_as_hex(knx_ip_cEMI_frame)
        except e.NotAPacketError:
            print("No payload found in UDP-package")
            continue

        if 'knx_ip_cEMI_frame' in locals():
            telegram_as_IP = t.KNX_IP_cEMI_Frame(knx_ip_cEMI_frame).asIP(receiver)
            if telegram_as_IP is None:
                continue
            send(telegram_as_IP, verbose = 0)
            print("packet send!")
        else:
            continue

def mapIncomingTrafficFromUSB(usb_file, receiver):
    print("USB-Mapper Online")
    fd = os.open(usb_file, os.O_RDONLY | os.O_NONBLOCK)
    while True:
        try:
            knx_frame = os.read(fd, 128)
            if knx_frame:
                print("NEW KNX_Telegram")
                telegram_as_IP = convertKNXtoIP(knx_frame, receiver)
                if telegram_as_IP is None:
                    continue
                send(telegram_as_IP, verbose = 0)
                print("packet send!")
        except BlockingIOError:
            pass 


def convertKNXtoIP(knx_package, receiver_network) -> Packet:
    if u.is_L_Data_Standard_Frame(knx_package):
        return t.L_Data_Standard_Frame(knx_package).asIP(receiver_network)
    elif u.is_L_Data_Extended_Frame(knx_package):
        return t.L_Data_Extended_Frame(knx_package).asIP(receiver_network)
    elif u.is_L_Poll_Data_Frame(knx_package):
        #poll_telegram = t.L_Poll_Data_Frame(knx_package)
        print("Telegram is L_Poll_Frame")
        return None
    elif u.isAck_Frame(knx_package):
        print("Ack was ignored")
        return None
    else:
        print("Illegal control field. Telegram type undefined")
        return None