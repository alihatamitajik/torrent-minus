import argparse
import configparser
import logging
import socket
from util import ip_port_type, TorrentProtocol, TorrentRequest as TR

PEER_CONFIG = 'conf/peer.conf'


class Peer:
    def __init__(self, config, args) -> None:
        self.tracker = args.tracker
        self.listen = args.listen
        if 'name' in args:
            logging.basicConfig(filename=f'log/{args.name}.log',
                                filemode='w',
                                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                level=logging.INFO)
            self.logger = logging.getLogger(args.name)
        else:
            self.logger = logging.getLogger()
        self.id = None
        self.key = None
        self.torrent = TorrentProtocol()
        self.buffer_size = int(config['SETTING']['BufferSize'])
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(self.listen)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(self.listen)

    def register(self):
        """register peer in the tracker and saves the id

        NOTE: This implementation does not provide any saving function in the 
        system to save the id of a peer though it can be handled.
        """
        self.udp.sendto(self.torrent.req(TR.REGISTER), self.tracker)
        res = self.torrent.read_response(self.udp.recv(self.buffer_size))
        self.id = res['id']
        self.key = res['secret']
        self.logger.info(f'Peer registered as id {self.id}')


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
    parser.add_argument('-n', '--name', required=False,
                        help='name of the log file. log file will be stored in log/[name].log')
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
    peer = Peer(config, args)
    peer.register()


if __name__ == "__main__":
    main()
