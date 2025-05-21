import util as u
import errors as e
import KNXasIPFactory

"""
on linux you need:
sudo /home/KNX/PycharmProjects/PythonProject/.venv/bin/python /home/KNX/KNXtoIP/main.py
"""

PacketSendOffInterface = "127.0"
PacketReceiverInterface = "127.0.0.1"

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



