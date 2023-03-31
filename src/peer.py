import argparse
import configparser
import logging
import socket
import hashlib

from pathlib import Path
from util import ip_port_type, TorrentProtocol, TorrentRequest as TR

PEER_CONFIG = 'conf/peer.conf'


class Peer:
    def __init__(self, config, args) -> None:
        self.tracker = args.tracker
        self.listen = args.listen
        self.dir = args.basedir
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
        self.file_keys = {}

    def register(self):
        """register peer in the tracker and saves the id

        NOTE: This implementation does not provide any saving function in the 
        system to save the id of a peer though it can be handled.
        """
        self.udp.sendto(self.torrent.req(TR.REGISTER), self.tracker)
        resp = self.torrent.read_response(self.udp.recv(self.buffer_size))
        self.id = resp['id']
        self.key = resp['secret'].encode('ISO-8859-1')
        self.logger.info(f'Peer registered as id {self.id}')

    def share(self, filename: str):
        """shares a file to the tracker

        This method will find size and checksum of the file and sends the
        information to the tracker. filename will be searched in the
        base-directory specified in the arguments.

        Protocol: when a peer wants to share a file it must provide name, size,
        and the MD5 checksum of the file in hex string format. Then tracker
        generates a key in the system and sends that back to peer. peer must
        encrypt the chunks of data sent to the other peer by that key (note: if
        size of each chunk is 1016 bytes then with Salsa20 it will be 1024 bytes
        size when encrypted).

        If it is  the first time the file is being shared, then it is assumed 
        that sender is providing the correct checksum of the file. If the peer
        downloaded the file before and if it provides the wrong checksum with
        the filename (or does not provide one) server sends status "error" to
        peer with a "msg". Else, status "ok" will be returned and peer is added
        to the list of peers. Sharing with correct checksum, tracker will send
        you the key to encrypt the file (the same as generated in the first
        place).

        Share request has an Alive request inside of it (i.e. first alive signal
        is assumed when share request is done). from then on, alive request must
        be sent in "ttl" intervals (which can be set between tracker and peers
        beforehand. defaults to 30 seconds).

        Rises:
            FileNotFoundError: if file cannot be found."""
        dir_filename = self.dir / filename
        with open(dir_filename, 'rb') as file:
            checksum = hashlib.md5()
            while chunk := file.read(8192):
                checksum.update(chunk)
            size = file.tell()
            self.udp.sendto(self.torrent.req(
                TR.SHARE,
                id=self.id,
                key=self.key,
                filename=filename,
                size=size,
                checksum=checksum.hexdigest()
            ), self.tracker)
            resp = self.torrent.read_response(self.udp.recv(self.buffer_size),
                                              key=self.key)
            if resp['status'] == 'ok':
                self.file_keys[filename] = resp['secret'].encode('ISO-8859-1')
                self.logger.info(f'[{filename}] shared')
            else:
                raise PermissionError(resp['msg'])


def parse_args():
    parser = argparse.ArgumentParser(
        prog='TorPeer',
        description="Simplified peer of torrent network",
        epilog="Spring23 - CE40443 - Assignment 2")
    parser.add_argument('mode',
                        choices=['get', 'share'],
                        help="Mode of the program. See the RFC for more.")
    parser.add_argument('file',
                        help="filename to share or get. note that filenames are unique identities of files in this simplified system.")
    parser.add_argument('tracker',
                        help="ip:port of the tracker server.",
                        type=ip_port_type)
    parser.add_argument('listen',
                        help="ip:port for listening when in share mode.",
                        type=ip_port_type)
    parser.add_argument('-n', '--name', required=False,
                        help='name of the log file. log file will be stored in "log/[name].log".')
    parser.add_argument('-d', '--basedir',
                        help='base directory of the peer. filenames will be searched concatenated to base directory. defaults to "tmp".',
                        default='tmp',
                        type=Path)
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
    peer.share(args.file)


if __name__ == "__main__":
    main()
