import struct
from .basic_functions import get_ipv4


class IPv4:
    def __init__(self, data):
        ver_header_length = data[0]

        self.ver = ver_header_length >> 4
        self.header = (ver_header_length & 15) * 4
        self.ttl, self.ip_proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        self.src = get_ipv4(src)
        self.dest = get_ipv4(dest)
        self.data = data[self.header:]