from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, UDP
from scapy.all import sniff
import errors as e
import KNXasIPFactory as f
import os

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