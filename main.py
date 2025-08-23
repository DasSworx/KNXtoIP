from util import util_general as u
import errors as e
import threading as th
import testing as test
from TunTap import startUpTun
import KNXasIPFactory as f


# To run the code:
# 1. Open project in VSCode
# 2. Open Bash terminal in VSCode
# 3. Run:
# sudo ./.venv/bin/python3 ./main.py

#PacketSendOffInterface = "127.0"
knx_receiver_Address = "42.42.0.0/16"

IDS_receiver_interface = "30.25.0.0/16"

#Boots up TUN Device
startUpTun("tun0", knx_receiver_Address)

startUpTun("IDS_tun", IDS_receiver_interface)

fd = test.getFileDescribtor("tun0")
fd2 = test.getFileDescribtor("IDS_tun")

#Start sending and receiving messages
Mapper = th.Thread(target = f.mapIncomingTraffic, args = (fd, IDS_receiver_interface))
IDS_stand_in = th.Thread(target = test.sniffer, args = [fd2])
Spam = th.Thread(target = test.spammer, args = ())
#Receiver = th.Thread(target = test.receivePackets, args = [fd])

#Receiver.start()
Mapper.start()
IDS_stand_in.start()
Spam.start()
