class NotAPacketError(Exception):
    pass

class InvalidKNXPacketError(Exception):
    pass

class InvalidChecksumError(Exception):
    pass

class notAMapperError(Exception):
    def __init__(self):
        super().__init__("\n\tThe chosen Mapper could no be found, please verify it exists \n\tAlternativly change the Mapper in the config.ini")

class TelegramDoesNotUseSequenceNumberError(Exception):
    def __init__(self):
        super().__init__("The telegram provided uses a service code, that does not use Sequence Numbers!")