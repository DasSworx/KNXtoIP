from scapy import *
from scapy.interfaces import show_interfaces
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import send, sendp, sniff
from scapy.config import conf

knxTestMessage = bytes([0b10110000,0b00000001,0b00000001,0b00010000,0b00000001,0b00000010,0b00000000,0b00000001,0b11001100])

test_package = IP(src = "127.0.0.2", dst = "127.0.0.15") / UDP() / Raw(load = knxTestMessage)

send(test_package)



#show_interfaces()