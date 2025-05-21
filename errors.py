class NotAPacketError(Exception):
    pass

class InvalidKNXPacketError(Exception):
    pass

class InvalidChecksumError(Exception):
    pass

class TelegramDoesNotUseSequenceNumberError(Exception):
    print("The telegram provided uses a service code, that does not use Sequence Numbers!")
    pass