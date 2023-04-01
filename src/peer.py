import argparse
import configparser
import logging
import socket
import hashlib
import time
import math
import random

from pathlib import Path
from util import ip_port_type, TorrentProtocol, TorrentRequest as TR
from util.decor import threaded
from util.encrypt import encrypt, decrypt

PEER_CONFIG = 'conf/peer.conf'


class Peer:
    def __init__(self, config, args) -> None:
        self.tracker = args.tracker
        self.listen = args.listen
        self.dir = args.basedir
        self.ttl = float(config['SETTING']['PTTL'])
        self.buffer_size = int(config['SETTING']['BufferSize'])
        self.chunk_size = int(config['SETTING']['ChunkSize'])
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

    @threaded
    def keep_alive(self):
        """Sends alive requests in ttl intervals

        Protocol: peers must sent a alive requests to the server so last alive
        parameter of each peer gets updated. This parameter is useful when 
        querying providers. If a provider is inactive for more than 2 ttl then
        it is assumed that it is become offline. also client information is
        updated with update port and ip request.
        """
        while True:
            time.sleep(self.ttl)
            self.send_to_tracker(TR.ALIVE)

    def handle_false_filename(self, filename, peer_sock, addr):
        """Handles if download peer requested a bad filename"""
        msg = "File Not Found. This incident will be reported to tracker."
        peer_sock.send(self.torrent.respond(status="error", msg=msg))
        peer_sock.close()
        self.logger.warning(
            f'({addr}) requested [{filename}] but does not exist.')
        self.send_to_tracker(TR.REMOVE, filename=filename)
        resp = self.get_response()
        if resp['status'] == 'ok':
            self.logger.info(f'false ({filename}) removed from tracker')
        else:
            self.logger.critical(
                f'false [{filename}] requested but tracker can\'t remove it')

    def send_file(self, file_dir: Path, key: bytes, peer_sock: socket.socket):
        """sends file to the peer in chunks

        Args:
            file_dir (Path): path of an available file
            key (bytes): encryption key of the file
            peer_sock (socket): socket of the download peer
        """
        peer_sock.settimeout(100)
        peer_sock.send(self.torrent.respond(
            status="ok", chunk=self.chunk_size))
        resp = self.torrent.read_response(peer_sock.recv(self.buffer_size))
        if resp['status'] == 'ok':
            with open(file_dir, 'rb') as file:
                while chunk := file.read(self.chunk_size - 8):
                    peer_sock.send(encrypt(chunk, key))
                    resp = self.torrent.read_response(
                        peer_sock.recv(self.buffer_size))
                    if resp['status'] != 'ok':
                        raise AssertionError('download discarded')
        else:
            raise AssertionError('download discarded')

    @threaded
    def handle_peer(self, peer_sock: socket.socket, addr):
        """Handle peer download

        Protocol: download peer makes a plaintext request to the a provider peer
        including non-encryption byte zero followed JSON respond with filename. 
        If provider does not have the file, it will respond with plain text err
        structure (i.e. status "error" and msg) and sends a remove request to
        tracker to remove the entry that shows this peer has the file (in case
        of file deleted or something).
        On the other hand if the peer has the file first it will send an ok
        JSON structure in plain text (with non-encrypted byte) and a chunk
        attribute which shows buffer size for receiving the file (if chunk size
        is 1016 there would be 1024 byte of data sent because encryption).
        After this download peer must send a confirmation ok structure so
        provider starts to send the data else an error structure. Also there is
        a 100 seconds timeout for sending ok to provider. provider needs an ok
        massage after each chunk of data. NOTE: download peer has the filesize 
        from tracker and it should keep count of the bytes received.
        """
        resp = self.torrent.read_response(peer_sock.recv(self.buffer_size))
        filename = resp['filename']
        self.logger.info(f'{addr} requested for [{filename}]')
        file_dir = self.dir / filename
        if file_dir.is_file():
            try:
                self.send_file(file_dir, self.file_keys[filename], peer_sock)
                self.logger.info(f'[{filename}] sent to {addr} successfully.')
            except:
                self.logger.error(f'Send [{filename}] to ({addr}) discarded.')
                peer_sock.close()
        else:
            self.handle_false_filename(filename, peer_sock, addr)

    @threaded
    def start_service(self):
        self.keep_alive()
        self.tcp.listen(10)
        while True:
            peer_sock, addr = self.tcp.accept()
            self.handle_peer(peer_sock, addr)

    def get_response(self):
        """receive response from tracker

        logs JSON responses in debug mode"""
        resp = self.torrent.read_response(self.udp.recv(self.buffer_size),
                                          key=self.key)
        self.logger.debug(resp)
        return resp

    def send_to_tracker(self, type: TR, **kwargs):
        """send kwargs to tracker

        logs requests bytes in debug mode"""
        req = self.torrent.req(type, id=self.id, key=self.key, **kwargs)
        self.logger.debug(req)
        self.udp.sendto(req, self.tracker)

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
            self.send_to_tracker(TR.SHARE, filename=filename, size=size,
                                 checksum=checksum.hexdigest())
            resp = self.get_response()
            if resp['status'] == 'ok':
                self.file_keys[filename] = resp['secret'].encode('ISO-8859-1')
                self.logger.info(f'[{filename}] shared')
            else:
                raise PermissionError(resp['msg'])

    def query(self, filename) -> dict:
        """Query providers of filename

        Protocol: peer use query request to find all peers that have the file.
        the first response only contains status of the query with following
        attributes:
            - status    : "ok" or "error" (str)
            - msg       : if "error", error massage (str)
            - parts     : if "ok", # of 1KB encrypted responses that have to
                          be received after first response (int)
            - secret    : if "ok", key to read file bytes from other peer. (str)
            - size      : if "ok", size of the file.
        parts can be zero meaning that there is no online provider. if part is
        positive #parts will be sent to the peer with following attribute:
            - provider  : list of the providers. there will be maximum of 30
                          providers in the list (Technical reason: each provider
                          will be sent as '(ip,port)' and ip is maximum 19 bytes
                          long and port is 5 bytes long when in string. To
                          ensure that we does not exceed the limit of 1KB 30 of
                          this struct is sent at maximum).
        """
        self.send_to_tracker(TR.QUERY, filename=filename)
        query = self.get_response()
        if query['status'] == 'ok':
            query['provider'] = []
            for _ in range(query['parts']):
                resp = self.get_response()
                query['provider'].extend(resp['provider'])
            self.logger.info(f'query for [{filename}] received.')
            return query
        else:
            raise LookupError(query['msg'])

    def download(self, filename, size, key, provider) -> bool:
        """download from peer

        returns true if download was successful else False"""
        self.tcp.connect(provider)
        self.tcp.send(self.torrent.respond(filename=filename))
        resp = self.torrent.read_response(self.tcp.recv(self.buffer_size))
        if resp['status'] == 'ok':
            chunk = resp['chunk']
            buffer_size = chunk + 8
            self.tcp.send(self.torrent.respond(status="ok"))
            file_dir = self.dir / filename
            with open(file_dir, 'wb') as file:
                for _ in range(int(math.ceil(size/chunk))):
                    file.write(decrypt(self.tcp.recv(buffer_size), key))
                    self.tcp.send(self.torrent.respond(status="ok"))
            self.logger.info(f'[{filename}] received from {provider}')
            return True
        else:
            self.logger.error(
                f'[{filename}] file does not exist in {provider}')
            return False

    def get(self, filename):
        """Query and download filename from peers"""
        query = self.query(filename)
        self.file_keys[filename] = query['secret'].encode('ISO-8859-1')
        num_provider = len(query['provider'])
        if num_provider == 0:
            raise IndexError('No Provider is online.')
        else:
            # retrial can be done for other providers but not implemented
            provider_index = random.randrange(num_provider)
            provider = query['provider'][provider_index]
            if not self.download(filename,
                                 query['size'],
                                 self.file_keys[filename],
                                 (provider[0], provider[1])):
                raise RuntimeError('Download failed.')


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
    try:
        peer.register()
        if args.mode == 'get':
            peer.get(args.file)
        peer.share(args.file)
        peer.start_service()
        # start the console
    except:
        peer.logger.exception('operation failed')


if __name__ == "__main__":
    main()
