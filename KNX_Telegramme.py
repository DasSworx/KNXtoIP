from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
import util.util_general as u
from keystore_manager import get_keystore
from enum import Enum
import errors as e

class Type(Enum):
    STANDARD = 0
    EXTENDED = 1

class KNX_TP1_Telegram():
    def get_type_of_telegram(self):
        if u.is_L_Data_Standard_Frame(self.telegram_as_byte_array):
            return Type.STANDARD
        elif u.is_L_Data_Extended_Frame(self.telegram_as_byte_array):
            return Type.EXTENDED
        else:
            raise e.TelegramTypeNotSupportedError
        
    def assamble_address(self, network, device_address):
        beginning = ".".join(network.split(".")[:2])
        int1 = device_address[0]
        int2 = device_address[1]
        address_as_string = f"{int1}.{int2}"
        print("address as string is:" + beginning + "." + address_as_string)
        return beginning + "." + address_as_string
    
    def calculate_checksum(self):
        checksum = 0b00000000
        for byte in self.telegram_as_byte_array[:-1]:
            checksum ^= byte
        checksum ^= 0b11111111
        return checksum
    
    def get_control_field(self):
        return self.telegram_as_byte_array[0]
    
    def checksum_is_valid(self):
        return self.checksum == self.calculate_checksum()
        
    def get_checksum(self):
        return self.telegram_as_byte_array[-1]
    
    def get_src(self):
        if self.type_of_telegram == Type.STANDARD:
            return self.telegram_as_byte_array[1:3]
        elif self.type_of_telegram == Type.EXTENDED:
            return self.telegram_as_byte_array[2:4]
        else:
            raise e.TelegramTypeNotSupportedError
        
    def get_dst(self):
        if self.type_of_telegram == Type.STANDARD:
            return self.telegram_as_byte_array[3:5]
        elif self.type_of_telegram == Type.EXTENDED:
            return self.telegram_as_byte_array[4:6]
        else:
            raise e.TelegramTypeNotSupportedError
    
    def get_hop_count(self):
        if self.type_of_telegram == Type.STANDARD:
            byte = self.telegram_as_byte_array[5]
            return (byte >> 4) & 0b111
        elif self.type_of_telegram == Type.EXTENDED:
            byte = self.telegram_as_byte_array[1]
            return (byte >> 4) & 0b111
        else:
            raise e.TelegramTypeNotSupportedError
    
    def get_data_len(self):
        if self.type_of_telegram == Type.STANDARD:
            byte = self.telegram_as_byte_array[5]
            return byte & 0b1111
        elif self.type_of_telegram == Type.EXTENDED:
            return self.telegram_as_byte_array[6]
        else:
            raise e.TelegramTypeNotSupportedError
    
    def get_APDU(self):
            len_of_telegram = len(self.telegram_as_byte_array)
            telegram_as_int = int.from_bytes(self.telegram_as_byte_array)
            telegram_as_int = ((telegram_as_int >> 8) << 6)
            aligned_telegram = telegram_as_int.to_bytes(len_of_telegram, "big")
            return aligned_telegram[-self.data_len-1:]

    def __init__(self, telegram_as_byte_array):
        self.telegram_as_byte_array = telegram_as_byte_array
        self.type_of_telegram = self.get_type_of_telegram()
        self.control_field = self.get_control_field()
        self.checksum = self.get_checksum()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.hop_count = self.get_hop_count()
        self.data_len = self.get_data_len()
        self.APDU = self.get_APDU()
    
    def as_IP(self, network_address) -> Packet:
        knxpacket = IP(src = self.assamble_address(network_address, self.src), 
                       dst = self.assamble_address(network_address, self.dst), 
                       ttl = self.hop_count) / UDP() / self.APDU

        if self.checksum_is_valid():
            return knxpacket
        else:
            knxpacket[IP].chksum = 0xFFFF
            return knxpacket

class L_Poll_Data_Frame:
    def get_control_field(self):
        return self.full_telegram[0]

    def get_src(self):
        return self.full_telegram[1:3]

    def get_dst(self):
        return self.full_telegram[3:5]

    def get_check_sum(self):
        return self.full_telegram[-1]

    def get_num_of_exp_poll_data(self):
        byte = self.full_telegram[6]
        return byte & 0b1111

    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array
        self.control_field = self.get_control_field()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.check_sum = self.get_check_sum()
        self.num_of_exp_poll_data = self.get_num_of_exp_poll_data()

class Ack_Frame:
    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array

class KNX_IP_cEMI_Frame:

    def assamble_address(self, network, device_address):
        beginning = ".".join(network.split(".")[:2])
        int1 = device_address[0]
        int2 = device_address[1]
        address_as_string = f"{int1}.{int2}"
        print("address as string is:" + beginning + "." + address_as_string)
        return beginning + "." + address_as_string
    
    def get_knx_ip_len(self):
        return self.full_telegram[0]
    
    def get_cEMI_frame(self):
        return self.full_telegram[self.knx_ip_len:]
    
    def get_cEMI_additional_header_len(self):
        return self.cEMI_frame[1]
    
    def get_APCI(self):
        tpci_apci = self.cEMI_frame[9+self.cEMI_additional_header_len:11+self.cEMI_additional_header_len]
        apci = bytes([tpci_apci[0] & 0x03]) + tpci_apci[1:]
        return apci
    
    def get_frame(self):
        return self.cEMI_frame[self.cEMI_additional_header_len+2 :]
    
    def get_src(self):
        return self.frame[2:4]
    
    def get_dst(self):
        return self.frame[4:6]
    
    def get_control1(self):
        return self.frame[0]

    def get_control2(self):
        return self.frame[1]
    
    def get_hop_count(self):
        return (self.control2 >> 4) & 0b00000111
    
    def get_payload(self):
        payload_w_tpci = self.cEMI_frame[(9+self.cEMI_additional_header_len):]
        payload = bytes([payload_w_tpci[0] & 0x03]) + payload_w_tpci[1:]
        return payload 

    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array
        self.knx_ip_len = self.get_knx_ip_len()
        self.cEMI_frame = self.get_cEMI_frame()
        self.cEMI_additional_header_len = self.get_cEMI_additional_header_len()
        self.frame = self.get_frame()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.control1 = self.get_control1()
        self.control2 = self.get_control2()
        self.hop_count = self.get_hop_count()
        self.APCI = self.get_APCI()
        self.payload = self.get_payload()
    
    def as_IP(self, network_address) -> Packet:
        e.printAPCI(self.APCI)
        if self.APCI == bytearray([0x03, 0xF1]):
            e.decryptingMessage()
            java_bytes = get_keystore().decryptAndVerify1(self.cEMI_frame)
            payload = bytearray((b & 0xFF) for b in java_bytes)
            e.printPayload(payload)
        else:
            payload = self.payload
        
        return IP(src = self.assamble_address(network_address, self.src), 
                       dst = self.assamble_address(network_address, self.dst), 
                       ttl = self.hop_count) / UDP() / payload