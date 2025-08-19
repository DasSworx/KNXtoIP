from util import util_general as u
import errors as e
import threading as th
import testing as test
from TunTap import startUpTun


# To run the code:
# 1. Open project in VSCode
# 2. Open Bash terminal in VSCode
# 3. Run:
# sudo ./.venv/bin/python3 ./main.py

#PacketSendOffInterface = "127.0"
tun0Address = "42.42.0.0/16"

#Boots up TUN Device
startUpTun("tun0", tun0Address)

fd = test.getFileDescribtor("tun0")

#Start sending and receiving messages
Sniff = th.Thread(target = test.sniffer, args = [fd])
Spam = th.Thread(target = test.spammer, args = ())
#Receiver = th.Thread(target = test.receivePackets, args = [fd])

#Receiver.start()
Sniff.start()
Spam.start()