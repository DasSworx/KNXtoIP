from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, UDP
from scapy.all import sniff
import errors as e
import KNXasIPFactory as f
import os
import fcntl
import struct

def stripDownToIP(pkt):
    strippedPkt = IP(pkt.bytes)
    strippedPkt.show()

def catch_eth(interface) -> Packet:
    eth_pkt = sniff(iface = interface, count = 1)[0]
    if IP in eth_pkt:
        ip_pkt = eth_pkt[IP] 
        return ip_pkt

def catch_traffic(interface) -> Packet:
    pkt = IP(os.read(interface, 4096))
    return pkt[0]


def obtain_payload(package) -> bytearray:
    if isinstance(package,Packet):
        try:
            udp = package[UDP]
        except IndexError:
            raise e.noUDPFoundError
        
        if udp.sport == 3671:
            try:
                data = package[Raw].load
                return data
            except IndexError:
                raise e.noRawDataFoundError
        else:
            raise e.wrongUDPPortError
    else:
        raise e.NotAPacketError
    

def is_L_Data_Standard_Frame(telegram):
    first_byte = telegram[0]
    if (first_byte >> 7) == 1 and ((first_byte >> 6) & 1) == 0 and ((first_byte >> 4) & 1) == 1:
        return True
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
    if first_byte & 0b00110011 == 0:
        return True
    else:
        return False

def choose_mapper(mapper_code):
    match mapper_code:
        case "USB"|"usb":
            print("Mapper set to USB")
            return f.map_incoming_traffic_from_USB
        case "Eth"|"eth"|"ETH":
            return f.map_incoming_traffic_from_eth
    raise e.notAMapperError

def print_bytes_as_hex(byte_array):
    print(byte_array.hex())

def receiver_with_log(interface):
    print("Receiver started")
    while True:
        packet = catch_traffic(interface)
        print("KNX PACKET AS IP: ")
        packet.show() 

def receiver_silent(interface):
    print("Receiver started")
    while True:
        os.read(interface, 4096)

IFF_TUN   = 0x0001   
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

def get_file_describtor(if_name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", if_name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd