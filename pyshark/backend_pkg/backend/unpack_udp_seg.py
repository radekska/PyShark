import struct


class UDP:
    def __init__(self, data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', data[:8])
        self.data = data[8:]
