class NotAPacketError(Exception):
    pass

class InvalidKNXPacketError(Exception):
    pass

class InvalidChecksumError(Exception):
    pass

class TelegramDoesNotUseSequenceNumberError(Exception):
    def __init__(self, message):
        print("The telegram provided uses a service code, that does not use Sequence Numbers!")
        super().__init__(message)