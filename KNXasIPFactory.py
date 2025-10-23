from scapy.packet import Packet
from scapy.sendrecv import send
import util.util_general as u
import KNX_Telegramme as t
import errors as e
from errors import newPacketMessage, packetSentMessage, newKNXTelegramMessage, printBytes
import os
from queue import Queue
import errors as e
import threading as th

def add_to_queue_from_eth(surveiled_interface, queue):
     while True:
        packet = u.catch_eth(surveiled_interface)
        newPacketMessage()
        try:
            knx_ip_cEMI_frame = u.obtain_payload(packet)

            if knx_ip_cEMI_frame is None:
                raise e.payloadIsEmptyError
            printBytes(knx_ip_cEMI_frame)
            queue.put(knx_ip_cEMI_frame)
        except Exception as e:
            print(e)
            continue

def map_and_send_telegrams_eth(receiver, queue):
    while True:
        try:
            telegram_as_IP = t.KNX_IP_cEMI_Frame(queue.get()).as_IP(receiver)   
            send(telegram_as_IP, verbose = 0)
            packetSentMessage()
        except Exception as e:
            print(e)
            continue

def map_incoming_traffic_from_eth(surveiled_interface, receiver):
    print("Eth-Mapper Online")
    knx_telegrams = Queue()
    
    Queing = th.Thread(target = add_to_queue_from_eth, args = [surveiled_interface, knx_telegrams])
    Queing.start()

    Map = th.Thread(target = map_and_send_telegrams_eth, args = [receiver, knx_telegrams])
    Map.start()

def read_telegrams_from_usb(fd, queue):
    while True:
        try:
            knx_frame = os.read(fd, 256)
            if knx_frame:
                newKNXTelegramMessage()
                queue.put(knx_frame)
        except BlockingIOError:
            pass

def convert_KNX_to_IP(receiver_network, queue) -> Packet:
    while True:
        try:
            telegram_as_IP = t.KNX_TP1_Telegram(queue.get()).as_IP(receiver_network)
            send(telegram_as_IP, verbose = 0)
        except e.TelegramTypeNotSupportedError:
            continue

def map_incoming_traffic_from_USB(usb_file, receiver):
    print("USB-MAPPER ONLINE")
    fd = os.open(usb_file, os.O_RDONLY | os.O_NONBLOCK)
    knx_telegrams = Queue()
    Queing = th.Thread(target = read_telegrams_from_usb, args = [fd, knx_telegrams])
    Queing.start()
    Map = th.Thread(target = convert_KNX_to_IP, args = [receiver, knx_telegrams])    
    Map.start()