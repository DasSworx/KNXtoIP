from pytun import TunTapDevice


def startUpTun():
    tun = TunTapDevice(name = "tunForKNX", addr = "")
    tun.addr = "42.42.0.0"
    tun.netmask = "255.255.0.0"
    tun.up()