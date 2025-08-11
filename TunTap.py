import subprocess


def startUpTun():
    try:
        subprocess.run(["sudo", "ip", "tuntap", "add", "dev", "tun0", "mode", "tun"], 
                       check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        if b'status 1' in e.stdout or b'status 1' in e.stderr:
            pass
        else:
            raise
    
    try:
        subprocess.run(["sudo", "ip", "addr", "add", "42.42.0.0/16", "dev", "tun0"], 
                       check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        if b'status 1' in e.stdout or b'status 1' in e.stderr:
            pass
        else:
            raise
    
    try:
        subprocess.run(["sudo", "ip", "link", "set", "tun0", "up"], 
                       check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        if b'status 1' in e.stdout or b'status 1' in e.stderr:
            pass
        else:
            raise