import Bytes as B

def isExtendedFrame(L_DataFrame):
    firstByte = B.Byte(L_DataFrame[0])
    if firstByte.getBit7() == 0:
        return True
    else:
        return False

def getDataFromExtenedFrame(knx_frame):
    return knx_frame[7:-1]

def getSourceFromExtendedFrame(knx_frame):
    third_byte = knx_frame[2]
    fourth_byte = knx_frame[3]
    source = str(third_byte) + "." + str(fourth_byte)
    return source

def getDestinationFromExtendedFrame(knx_frame):
    fifth_byte = knx_frame[4]
    sixth_byte = knx_frame[5]
    destination = str(fifth_byte) + "." + str(sixth_byte)
    return destination

#the extended frame knows two address types: 0 for point to point communication and 1 for all multicast shenanigans
def getAddressTypeFromExtendedFrame(knx_frame) -> int:
    extendedControlField = B.Byte(knx_frame[1])
    return extendedControlField.getBit7()

def getHopCountFromExtendedFrame(knx_frame) -> int:
    extendedControlField = knx_frame[1]
    return (extendedControlField >> 4) & 0x07
