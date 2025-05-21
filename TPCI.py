from enum import Enum
import util as u

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

def obtain_transport_layer_service_code(knx_telegram) -> TransportLayerServiceCode:
    if u.isStandardFrame(knx_telegram):
        TPCI1 = knx_telegram[5]
        TPCI2 = knx_telegram[6]
    else:
        TPCI1 = knx_telegram[6]
        TPCI2 = knx_telegram[7]
    addressType = (TPCI1 >> 7) & 1
    if addressType == 1:
        if ((TPCI2 >> 2) &1) == 1:
            return TransportLayerServiceCode(3)
        else:
            #TODO: unterscheide zwischen standard und extended und unterscheide dataBroadcast bzw. dataGroupPDU
    else:
        #TODO: unterscheide die restlichen Service Codes