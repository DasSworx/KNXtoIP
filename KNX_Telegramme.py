class L_Data_Standard_Frame:
    def get_control_field(self):
        return self.full_telegram[0]

    def get_src(self):
        return self.full_telegram[1:3]

    def get_dst(self):
        return self.full_telegram[3:5]

    def get_hop_count(self):
        byte = self.full_telegram[5]
        return (byte >> 4) & 0b111

    def get_data_len(self):
        byte = self.full_telegram[5]
        return byte & 0b1111

    def get_check_sum(self):
        return self.full_telegram[-1]

    def get_TPCI(self):
        byte = self.full_telegram[6]
        return (byte >> 2) & 0b111111

    def get_APDU(self):
            binary = int.from_bytes(self.full_telegram)
            return (binary >> 8) & ((1 << ((self.data_len * 8) + 2)) -1)

    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array
        self.control_field = self.get_control_field()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.hop_count = self.get_hop_count()
        self.data_len = self.get_data_len()
        self.checksum = self.get_check_sum()
        self.TPCI = self.get_TPCI()
        self.APDU = self.get_APDU()

class L_Data_Extended_Frame:
    def get_control_field(self):
        return self.full_telegram[0]

    def get_extended_control_field(self):
        return self.full_telegram[1]

    def get_src(self):
        return self.full_telegram[2:4]

    def get_dst(self):
        return self.full_telegram[4:6]

    def get_data_len(self):
        return self.full_telegram[6]

    def get_TPCI(self):
        byte = self.full_telegram[7]
        return byte >> 2

    def get_checksum(self):
        return self.full_telegram[-1]

    def get_APDU(self):
        binary = int.from_bytes(self.full_telegram)
        return (binary >> 8) & ((1 << ((self.data_len * 8) + 2)) - 1)

    def get_hop_count(self):
        byte = self.full_telegram[1]
        return (byte >> 4) & 0b111

    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array
        self.control_field = self.get_control_field()
        self.extended_control_field = self.get_extended_control_field()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.data_len = self.get_data_len()
        self.TPCI = self.get_TPCI()
        self.checksum = self.get_checksum()
        self.APDU = self.get_APDU()
        self.hop_count = self.get_hop_count()

class L_Poll_Data_Frame:
    def get_control_field(self):
        return self.full_telegram[0]

    def get_src(self):
        return self.full_telegram[1:3]

    def get_dst(self):
        return self.full_telegram[3:5]

    def get_check_sum(self):
        return self.full_telegram[-1]

    def get_num_of_exp_poll_data(self):
        byte = self.full_telegram[6]
        return byte & 0b1111

    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array
        self.control_field = self.get_control_field()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.check_sum = self.get_check_sum()
        self.num_of_exp_poll_data = self.get_num_of_exp_poll_data()

class Ack_Frame:
    def __init__(self, telegram_as_byte_array):
        self.full_telegram = telegram_as_byte_array