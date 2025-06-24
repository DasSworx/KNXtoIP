def getSourceFromPollFrame(knx_package) -> str:
    secondByte = knx_package[1]
    thirdByte = knx_package[2]
    source = str(secondByte) + "." + str(thirdByte)
    return source

def getDestinationFromStandardFrame(knx_package) -> str:
    fourthByte = knx_package[3]
    fifthByte = knx_package[4]
    destination = str(fourthByte) + "." + str(fifthByte)
    return destination