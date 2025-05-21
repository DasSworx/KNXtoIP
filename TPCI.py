from enum import Enum
import util as u
from errors import TelegramDoesNotUseSequenceNumberError


class TransportLayerServiceCode(Enum):
    DATA_BROADCAST_PDU = 1
    DATA_GROUP_pdu = 2
    DATA_TAG_GROUP = 3
    DATA_INDIVIDUAL_PDU = 4
    DATA_CONNECTED_PDU = 5
    CONNECT_PDU = 6
    DISCONNECT_PDU = 7
    ACK_PDU = 8
    NAK_PDU = 9

#Alias für TransportLayerServiceCode
T = TransportLayerServiceCode

def obtain_transport_layer_service_code(knx_telegram) -> TransportLayerServiceCode:
    #obtaining the TPCI and dst dependend on standard or extended frame
    if u.isStandardFrame(knx_telegram):
        TPCI1 = knx_telegram[5]
        TPCI2 = knx_telegram[6]
        dst = u.getDestinationFromStandardFrame(knx_telegram)
    else:
        TPCI1 = knx_telegram[6]
        TPCI2 = knx_telegram[7]
        dst = u.getDestinationFromExtendedFrame(knx_telegram)

    #obtains the named bits from the TPCI
    addressTypeField = (TPCI1 >> 7) & 1
    controlTypeField = (TPCI2 >> 7) & 1
    numberedField = (TPCI2 >> 6) &1

    if addressTypeField == 1:
        if ((TPCI2 >> 2) & 1) == 1:
            return TransportLayerServiceCode(3)
        else:
                if dst == 0:
                    return TransportLayerServiceCode(1)
                else:
                    return TransportLayerServiceCode(2)
    else: #addressField is 0
        if controlTypeField == 0:
            if numberedField == 0:
                return TransportLayerServiceCode(4)
            else: #numberedField is 1
                return TransportLayerServiceCode(5)
        else: #controlField is 1
            if numberedField == 0:
                if (TPCI2 & 1) == 0:
                    return TransportLayerServiceCode(6)
                else:
                    return TransportLayerServiceCode(7)
            else: #numberedField is 1
                if (TPCI2 & 1) == 0:
                    return TransportLayerServiceCode(8)
                else:
                    return TransportLayerServiceCode(9)

def getSequenceNumberFromStandard(knx_telegram):
    if obtain_transport_layer_service_code(knx_telegram) in (T.DATA_CONNECTED_PDU, T.ACK_PDU, T.NAK_PDU):
        return (knx_telegram[6] >> 2) & 0x0f
    else:
        raise TelegramDoesNotUseSequenceNumberError

def getSequenceNumberFromExtended(knx_telegram):
    if obtain_transport_layer_service_code(knx_telegram) in (T.DATA_CONNECTED_PDU, T.ACK_PDU, T.NAK_PDU):
        return (knx_telegram[7] >> 2) & 0x0f
    else:
        raise TelegramDoesNotUseSequenceNumberError