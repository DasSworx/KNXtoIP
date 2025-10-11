from scapy.packet import Packet
from scapy.sendrecv import send
import util.util_general as u
import KNX_Telegramme as t
import errors as e
import os



def map_incoming_traffic_from_eth(surveiled_interface, receiver):
    print("Eth-Mapper Online")
    while True:
        packet = u.catch_eth(surveiled_interface)
        print("NEW PACKET!")
        try:
            knx_ip_cEMI_frame = u.obtain_payload(packet)

            if knx_ip_cEMI_frame is None:
                raise e.payloadIsEmptyError
            u.print_bytes_as_hex(knx_ip_cEMI_frame)

            telegram_as_IP = t.KNX_IP_cEMI_Frame(knx_ip_cEMI_frame).as_IP(receiver)
                        
            send(telegram_as_IP, verbose = 0)
            print("Packet send!")

        except Exception as e:
            print(e)
            continue

def map_incoming_traffic_from_USB(usb_file, receiver):
    print("USB-MAPPER ONLINE")
    fd = os.open(usb_file, os.O_RDONLY | os.O_NONBLOCK)
    while True:
        try:
            knx_frame = os.read(fd, 256)
            if knx_frame:
                print("NEW KNX_Telegram")
                telegram_as_IP = convert_KNX_to_IP(knx_frame, receiver)
                if telegram_as_IP is None:
                    continue
                send(telegram_as_IP, verbose = 0)
        except BlockingIOError:
            pass


def convert_KNX_to_IP(knx_package, receiver_network) -> Packet:
    try:
        return t.KNX_TP1_Telegram(knx_package).as_IP(receiver_network)
    except e.TelegramTypeNotSupportedError:
        return None