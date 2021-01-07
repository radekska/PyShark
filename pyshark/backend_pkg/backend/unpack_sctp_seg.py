import struct


class SCTP:
    def __init__(self, data):
        self.src_port, self.dest_port, self.ver_tag, self.checksum, = struct.unpack(
            '! H H L L', data[:12])
        self.chunks = dict()
        cnt = 1
        data_legnth = len(data[12:])

        for i in range(12, data_legnth, 8):
            if i+8 < data_legnth:
                chnk_type, chnk_flags, chnk_length, chnk_data = struct.unpack('! B B H L', data[12 + i: 12 + i + 8])
                self.chunks[cnt] = {"chnk_type": chnk_type, "chnk_flags": chnk_flags,
                                                  "chnk_length": chnk_length, "chnk_data": chnk_data}
                cnt += 1

