#verbose Levels: 
#0: only critical errors
#1:Error
#2: Warning
#3: Info
#4: Debug

import configparser
config = configparser.ConfigParser()
config.read("config.ini")

#CRITICAL ERRORS

class notAMapperError(Exception):
    def __init__(self):
        super().__init__()
        print("\n\tCRITICAL: The chosen Mapper could no be found, please verify it exists \n\tAlternativly change the Mapper in the config.ini")

class networkToSmallError(Exception):
    def __init__(self):
        super().__init__()
        print("\n\tCRITICAL: The size of the network provided is not large enough. Minimum required is /16")

#WARNINGS

class TelegramDoesNotUseSequenceNumberError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 1:
            print("\n\tWARNING: The telegram provided uses a service code, that does not use Sequence Numbers!")

class cEMIFrameCouldNotBeMappedError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 1:
            print("\n\tWARNING: The mapping of the provided cEMI-frame failed")

#INFO

class NotAPacketError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tINFO: Data received cannot be resolved to a packet")

class payloadIsEmptyError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tINFO: The raw data segment of the package had a length of zero")

class noRawDataFoundError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tINFO: The package did not contain any raw data")

class noUDPFoundError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tINFO: The package did not contain a UDP payload")

class wrongUDPPortError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tINFO: The port used by UDP does not belong to KNX")

class TelegramTypeNotSupportedError(Exception):
    def __init__(self):
        super().__init__()
        if int(config["Settings"]["verbose"]) < 2:
            print("\n\tINFO: The control byte of the provided telegram does not match any supported type")