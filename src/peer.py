import argparse
import configparser
import logging
from util import ip_port_type

PEER_CONFIG = 'conf/peer.conf'


class Peer:
    def __init__(self, config) -> None:
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        prog='TorPeer',
        description="Simplified peer of torrent network",
        epilog="Spring23 - CE40443 - Assignment 2")
    parser.add_argument('mode',
                        choices=['get', 'share'],
                        help="Mode of the program. See the RFC for more.")
    parser.add_argument('tracker',
                        help="ip:port of the tracker server",
                        type=ip_port_type)
    parser.add_argument('listen',
                        help="ip:port for listening when in share mode",
                        type=ip_port_type)
    return parser.parse_args()


def load_conf():
    config = configparser.ConfigParser()
    read = config.read(PEER_CONFIG)
    if not read:
        logging.fatal(f'CONFIG FILE NOT FOUND')
        exit(1)
    return config


def main():
    args = parse_args()
    config = load_conf()


if __name__ == "__main__":
    main()
