import threading
import time

from scapy import *
from scapy.interfaces import show_interfaces
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import send, sendp, sniff
from scapy.config import conf
import util as u

"""
on linux you need:
sudo /home/KNX/PycharmProjects/PythonProject/.venv/bin/python /home/KNX/KNXtoIP/testing.py
"""


def sendingMessage():
    knxTestMessage = bytes(
        [0b10110000, 0b00100011, 0b00000101, 0b00010000, 0b00000001, 0b00000010, 0b00000000, 0b00000001, 0b10100010])

    test_package = IP(src="127.0.0.2", dst="127.0.0.15") / UDP() / Raw(load=knxTestMessage)
    send(test_package)
    time.sleep(10)
    send(test_package)

def analysePackages():
    while True:
        new_package = u.catch_traffic()
        new_package.show()
        package_data = u.obtain_payload(new_package)
        package_sender = u.getSource(package_data)
        print(f"source is: {package_sender}")

senderThread = threading.Thread(target = sendingMessage)
analyserThread = threading.Thread(target = analysePackages)

analyserThread.start()
senderThread.start()

senderThread.join()
analyserThread.join()

#show_interfaces()