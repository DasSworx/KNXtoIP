from util import util_general as u
from util import util_config as u_c
import errors as e
import threading as th
import testing as test
from TunTap import start_up_tun
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

u_c.confirm_network_mask(config["Settings"]["outPort"])

start_up_tun("IDS_tun", config["Settings"]["outPort"])

fd2 = u.get_file_describtor("IDS_tun")

#Start sending and receiving messages
chosen_mapper = u.choose_mapper(config["Settings"]["Mapper"])
Mapper = th.Thread(target = chosen_mapper, args = (config["Settings"]["inPort"], config["Settings"]["outPort"]))


Receiver = th.Thread(target = u.receiver_with_log, args = [fd2])

Mapper.start()
Receiver.start()

"""
test.showKNXTrafficOverUSB(config["Settings"]["inPort"])
"""