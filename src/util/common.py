import argparse
import ipaddress

def ip_port_type(val: str):
    vals = val.split(":")
    if len(vals) != 2:
        raise argparse.ArgumentTypeError(
            'ip:port error (e.g. 127.0.0.1:12345)')
    if not vals[1].isdigit():
        raise argparse.ArgumentTypeError(
            f'invalid port ({vals[1]}). port value must be digits.')
    port = int(vals[1])
    if port > 65536 or port < 0:
        raise argparse.ArgumentTypeError(
            f'invalid port ({port}). port number must be in range of [0, 65536].')
    if vals[0] == '':
        return ('', port)
    try:
        ip = ipaddress.ip_address(vals[0])
        if ip.version != 4:
            raise argparse.ArgumentTypeError(
                f'invalid ip ({vals[0]}). use valid IPv4 address (e.g. 127.0.0.1).')
        return (vals[0], vals[1])
    except:
        raise argparse.ArgumentTypeError(
            f'invalid ip ({vals[0]}). use valid IPv4 address (e.g. 127.0.0.1).')


class ASCII:
    NUL = '\x00'
    SOH = '\x01'
    STX = '\x02'
    ETX = '\x03'
    EOT = '\x04'
    ENQ = '\x05'
    ACK = '\x06'
    BEL = '\x07'
    NAK = '\x15'
    SYN = '\x16'
    FS = '\x1C'
