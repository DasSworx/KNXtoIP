from util import util_standard as u
import errors as e
from pytun import TunTapDevice
from pytun import IFF_TUN
from time import sleep

"""
To run the code:
1. Open project in VSCode
2. Open Bash terminal in VSCode
3. Run:
sudo ./.venv/bin/python3 ./main.py
"""

#PacketSendOffInterface = "127.0"
tunAddress = "42.42.0.0"
"""
while True:
    packet = u.catch_traffic()
    try:
        packetData = u.obtain_payload(packet)
    except e.NotAPacketError:
        print("No payload found in UDP-package")

    if packetData in globals():

        #standart message:
        if u.isStandardFrame(packetData):
            if
        #extended frame:
        else:

    else:
        continue

"""
tun = TunTapDevice(flags = IFF_TUN)
tun.addr = tunAddress
tun.netmask = "255.255.0.0"
tun.mtu = 1500
tun.up()

sleep(300)