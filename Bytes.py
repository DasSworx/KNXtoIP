class Byte:
    def __init__(self, byte):
        self.bit0 = byte & 1
        self.bit1 = (byte >> 1) & 1
        self.bit2 = (byte >> 2) & 1
        self.bit3 = (byte >> 3) & 1
        self.bit4 = (byte >> 4) & 1
        self.bit5 = (byte >> 5) & 1
        self.bit6 = (byte >> 6) & 1
        self.bit7 = (byte >> 7) & 1

    #Getter
    def getBit0(self):
        return self.bit0
    def getBit1(self):
        return self.bit1
    def getBit2(self):
        return self.bit2
    def getBit3(self):
        return self.bit3
    def getBit4(self):
        return self.bit4
    def getBit5(self):
        return self.bit5
    def getBit6(self):
        return self.bit6
    def getBit7(self):
        return self.bit7

    #Setter
    def setBit0(self, value):
        self.bit0 = value
    def setBit1(self, value):
        self.bit1 = value
    def setBit2(self, value):
        self.bit2 = value
    def setBit3(self, value):
        self.bit3 = value
    def setBit4(self, value):
        self.bit4 = value
    def setBit5(self, value):
        self.bit5 = value
    def setBit6(self, value):
        self.bit6 = value
    def setBit7(self, value):
        self.bit7 = value

    #Util
    def returnAsInt(self):
        num = 0
        num = num | self.bit0
        num = num | (self.bit1 << 1)
        num = num | (self.bit2 << 2)
        num = num | (self.bit3 << 3)
        num = num | (self.bit4 << 4)
        num = num | (self.bit5 << 5)
        num = num | (self.bit6 << 6)
        num = num | (self.bit7 << 7)
        return num
