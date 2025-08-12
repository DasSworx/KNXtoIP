import subprocess


def startUpTun():
    try:
        subprocess.run(["sudo", "ip", "tuntap", "add", "dev", "tun0", "mode", "tun"], 
                       check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        print("Added Tun device")
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode().strip()
        if "Device or resource busy" in err_msg:
            print("Device already existend")
        else:
            print("Error during creation")
            raise
    
    try:
        subprocess.run(["sudo", "ip", "addr", "add", "42.42.0.0/16", "dev", "tun0"], 
                       check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        print("Changed TUN address")
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode().strip()
        if "Address already assigned" in err_msg:
            print("Device already on correct ip")
        else:
            print("Error during configuration")
            raise
    
    try:
        subprocess.run(["sudo", "ip", "link", "set", "tun0", "up"], 
                       check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        print("TUN was set to up")
    except subprocess.CalledProcessError as e:
        if b'status 1' in e.stdout or b'status 1' in e.stderr:
            print("Device already up")
        else:
            print("error during activation")
            raise