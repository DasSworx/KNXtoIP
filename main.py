from util import util_general as u
import errors as e
import threading as th
import testing as test
from TunTap import startUpTun
import KNXasIPFactory as f
import configparser
from scapy.all import sniff


# To run the code:
# 1. Open project in VSCode
# 2. Open Bash terminal in VSCode
# 3. Run:
# sudo ./.venv/bin/python3 ./main.py

config = configparser.ConfigParser()
config.read("config.ini")

#Boots up TUN Device
#startUpTun("tun0", config["Settings"]["inPort"])

startUpTun("IDS_tun", config["Settings"]["outPort"])

#fd = test.getFileDescribtor("tun0")
fd2 = test.getFileDescribtor("IDS_tun")

#Start sending and receiving messages
chosen_mapper = u.chooseMapper(config["Settings"]["Mapper"])
Mapper = th.Thread(target = chosen_mapper, args = (config["Settings"]["inPort"], config["Settings"]["outPort"]))


IDS_stand_in = th.Thread(target = test.sniffer, args = [fd2])
#Spam = th.Thread(target = test.spammer, args = ())
#Receiver = th.Thread(target = test.receivePackets, args = [fd])

#Receiver.start()
Mapper.start()
IDS_stand_in.start()
#Spam.start()
