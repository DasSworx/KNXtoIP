#verbose Levels: 
#0: only critical errors
#3: Warning
#4: Info
#5: Debug

import configparser
config = configparser.ConfigParser()
config.read("config.ini")

#CRITICAL ERRORS

class notAMapperError(Exception):
    def __init__(self):
        super().__init__()
        print("\n\tThe chosen Mapper could no be found, please verify it exists \n\tAlternativly change the Mapper in the config.ini")

class networkToSmallError(Exception):
    def __init__(self):
        super().__init__()
        print("\n\tThe size of the network provided is not large enough. Minimum required is /16")

#WARNINGS

class TelegramDoesNotUseSequenceNumberError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("The telegram provided uses a service code, that does not use Sequence Numbers!")

class cEMIFrameCouldNotBeMappedError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tThe mapping of the provided cEMI-frame failed")

#INFO

class NotAPacketError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 3:
            print("\n\tData received cannot be resolved to a packet")

class payloadIsEmptyError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 3:
            print("\n\tThe raw data segment of the package had a length of zero")

class noRawDataFoundError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 3:
            print("\n\tThe package did not contain any raw data")

class noUDPFoundError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 3:
            print("\n\tThe package did not contain a UDP payload")

class wrongUDPPortError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 3:
            print("\n\tThe port used by UDP does not belong to KNX")

class TelegramTypeNotSupportedError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 3:
            print("\n\tThe control byte of the provided telegram does not match any supported type")