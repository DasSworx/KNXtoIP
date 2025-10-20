from time import sleep
import errors as e
import os
import fcntl
import struct
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, send
import TunTap as t
from util import util_general as u
from util import util_config as u_c

knx_Standard_Data_Frame = bytes(
        [0b10110000, 0b00100011, 0b00000101, 0b00010000, 0b00000001, 0b00010010, 0b00000000, 0b00000001, 0b00000000, 0b01101011])

knx_Extended_Data_Frame = bytes(
    [0b00010000, 0b01010000, 0b11101111, 0b00001111, 0b00111010, 0b01010101, 0b00010000, 0b01000001, 
     0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 
     0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000, 0b11110000,
     0b01100001]
)

KNX_UDP_cEMI = "0e570e570019dd730610053000112900bcd01103000201008000"
cEMI_Frame = UDP(bytearray.fromhex(KNX_UDP_cEMI))


def sending_message():
    #test_package = IP(src="42.42.0.21", dst="42.42.0.15") / UDP(dport = 12345) / Raw(load=knx_Extended_Data_Frame)
    test_package = IP(src = "42.42.0.21", dst = "42.42.0.15")/ cEMI_Frame
    send(test_package, verbose = 0)

def analyse_packages():
    while True:
        new_package = u.catch_traffic()
        new_package.show()
        package_data = u.obtain_payload(new_package)
        package_sender = u.getSourceFromStandardFrame(package_data)
        print(f"source is: {package_sender}")

def spammer():
    print("Spammer online")
    seq_nr = 0
    while True:
        e.sendingTestMessage(seq_nr)
        sending_message()
        seq_nr += 1
        sleep(5)
        
def show_KNX_traffic_over_USB(usb_file):
    fd = os.open(usb_file, os.O_RDONLY | os.O_NONBLOCK)
    while True:
        try:
            knx_frame = os.read(fd, 128)
            if knx_frame:
                print(knx_frame)
        except BlockingIOError:
            pass 

def boot_up_test_inport(interface_name, net_address):
    u_c.confirm_network_mask(net_address)
    t.start_up_tun(interface_name, net_address)
    return u.get_file_describtor(interface_name)