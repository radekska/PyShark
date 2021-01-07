import textwrap
import ipaddress


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def get_ipv4(bytes_addr):
    return '.'.join(map(str, bytes_addr))


def get_ipv6(bytes_addr6):
    bytes_addr6 = str(ipaddress.IPv6Address(bytes_addr6))
    return bytes_addr6


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
