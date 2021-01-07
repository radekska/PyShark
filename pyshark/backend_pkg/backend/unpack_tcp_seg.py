import struct


class TCP:
    def __init__(self, data):

        if len(data) > 13:
            self.src_port, self.dest_port, self.sequence, self.acknowledge, offset_reserved_flags = struct.unpack(
                '! H H L L H', data[:14])
            self.offset = (offset_reserved_flags >> 12) * 4
            self.flag_urg = (offset_reserved_flags & 32) >> 5
            self.flag_ack = (offset_reserved_flags & 16) >> 4
            self.flag_psh = (offset_reserved_flags & 8) >> 3
            self.flag_rst = (offset_reserved_flags & 4) >> 2
            self.flag_syn = (offset_reserved_flags & 2) >> 1
            self.flag_fin = (offset_reserved_flags & 1)
            self.data = data[self.offset:]
        else:
            self.src_port, self.dest_port = struct.unpack(
                '! H H', data)
