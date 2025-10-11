class NotAPacketError(Exception):
    pass

class InvalidKNXPacketError(Exception):
    pass

class InvalidChecksumError(Exception):
    pass

class networkToSmallError(Exception):
    def __init__(self):
        super().__init__("\n\tThe size of the network provided is not large enough. Minimum required is /16")

class cEMIFrameCouldNotBeMappedError(Exception):
    def __init__(self):
        super().__init__("\n\tThe mapping of the provided cEMI-frame failed")

class payloadIsEmptyError(Exception):
    def __init__(self):
        super().__init__("\n\tThe raw data segment of the package had a length of zero")

class noRawDataFoundError(Exception):
    def __init__(self):
        super().__init__("\n\tThe package did not contain any raw data")

class noUDPFoundError(Exception):
    def __init__(self):
        super().__init__("\n\tThe package did not contain a UDP payload")

class wrongUDPPortError(Exception):
    def __init__(self):
        super().__init__("\n\tThe port used by UDP does not belong to KNX")

class TelegramTypeNotSupportedError(Exception):
    def __init__(self):
        super().__init__("\n\tThe control byte of the provided telegram does not match any supported type")

class notAMapperError(Exception):
    def __init__(self):
        super().__init__("\n\tThe chosen Mapper could no be found, please verify it exists \n\tAlternativly change the Mapper in the config.ini")

class TelegramDoesNotUseSequenceNumberError(Exception):
    def __init__(self):
        super().__init__("The telegram provided uses a service code, that does not use Sequence Numbers!")