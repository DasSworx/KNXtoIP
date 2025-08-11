from util import util_general as u
import errors as e
import threading as th
import testing as test
import TunTap


# To run the code:
# 1. Open project in VSCode
# 2. Open Bash terminal in VSCode
# 3. Run:
# sudo ./.venv/bin/python3 ./main.py

#PacketSendOffInterface = "127.0"
tunAddress = "42.42.0.0"

#Boots up TUN Device
TunTap.startUpTun

fd = test.getFileDescribtor("tun0")

#Start sending and receiving messages
Sniff = th.Thread(target = test.sniffer, args = ())
Spam = th.Thread(target = test.spammer, args = ())
Receiver = th.Thread(target = test.receivePackets, args = fd)

Receiver.start()
Sniff.start()
Spam.start()