import argparse
import configparser
import socket
import signal
import threading
import logging
import logging.config
import json
import time

from functools import wraps
from util import ip_port_type, TorrentProtocol, TorrentRequest as TR
from util.encrypt import generate_key

SERVER_CONFIG = 'conf/server.conf'


def threaded(fn):
    """Threaded decorator

    This decorator will run a function or method in a new thread
    """
    def run(*args, **kwargs):
        t = threading.Thread(target=fn, args=args, kwargs=kwargs)
        t.start()
        return t
    return run


class UdpServer:
    """UDP server

    This server will create a udp socket on ip and port specified and then
    listen to it by `start` method. 

    Each request received, it'll be covered with `handle` method in a new 
    thread.

    This server can be shuted-down by keyboard interrupt (UNIX ONLY. Windows
    systems does not support this and you should close the terminal or kill
    the process).
    """

    def __init__(self, conf) -> None:
        """Initialize

        Creates a socket and binds it with port number and ip address specified
        in the config. It also sets the buffer size from the """
        signal.signal(signal.SIGINT, self.handle_signal)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((conf['NET']['Ip'], int(conf['NET']['Port'])))
        self.BUFFER_SIZE = int(conf['SETTING']['BufferSize'])

    def start(self):
        """This method will listen on the socket and assign a new thread to 
        handle the incoming requests.

        This method is blocking and supposed to block the program forever unless
        a keyboard interrupt receives. In that case, it will execute on_exit
        method and end the program. see handle_signal"""
        while True:
            msg, client = self.sock.recvfrom(self.BUFFER_SIZE)
            self.handle(msg, client)

    @threaded
    def handle(self, msg, client):
        """Handle incoming requests

        This method should be implemented by the child class. UDP server class
        itself DOES NOT provide this functionality"""
        raise NotImplementedError(f'`handle` METHOD NOT IMPLEMENTED')

    def handle_signal(self, signal, frame):
        """Executes on_exit method and end the program"""
        self.on_exit()
        exit(0)

    def on_exit(self):
        """Executed before ending program after keyboard interrupt"""
        print('Shutting down UDP server...')


class TorFile:
    def __init__(self, name, size, checksum) -> None:
        self.name = name
        self.size = size
        self.checksum = checksum
        self.key = generate_key()


class Peer:
    def __init__(self, id, client, key) -> None:
        self.lock = threading.Lock()
        self.files = []
        self.alive = True
        self.client = client
        self.key = key
        self.id = id


EMPTY_PEER = Peer(None, None, None)


def check_missing(type: TR):
    def _decorator(fn):
        @wraps(fn)
        def wrapper(self, *args, **kwargs):
            """If there are missing must, it will send an error massage to client"""
            client = args[0]
            missing = self.torrent.missing_fields(type, kwargs)
            if missing:
                id = kwargs['id']
                self.peer_logger.warning(
                    f"({id}) requested {type} without fields {missing}")
                self.send_error(id, client, f"missing {missing}")
            else:
                fn(self, *args, **kwargs)
        return wrapper
    return _decorator


class Tracker(UdpServer):
    """Tracker


    Tracker server keeps track of the peer downloads, wether it's done or not
    and torrent db which for each filename keep track of alive peers.
    """

    def __init__(self, conf) -> None:
        """Initialize"""
        super().__init__(conf)
        self._init_logger(conf)
        self.ttl = float(conf['SETTING']['PTTL'])
        self.torrent = TorrentProtocol()
        self.peer_lock = threading.Lock()
        self.peer_db = {}
        self.last_id = 0
        self.file_lock = threading.Lock()
        self.file_db = {}
        self.provider_lock = threading.Lock()
        self.providers = set()  # set of tuple(filename, id)s of providers

    def _init_logger(self, conf):
        logging.config.fileConfig(conf['SETTING']['LoggerConfig'])
        self.logger = logging.getLogger('LOGGER')
        self.error_logger = logging.getLogger('INTERNAL')

    @threaded
    def start_server(self):
        """Starts server in a new thread

        This will cause a non-blocking execution of the server. This is could be
        beneficial when we add console for the tracker."""
        self.start()

    def handle(self, b_msg: bytes, client):
        """Handles requests according to the protocol's RFC (!)"""
        try:
            r_type, fields = self.torrent.read_req(b_msg, self.key_extractor)
            getattr(self, f"_handle_{r_type}")(client, **fields)
        except:
            self.error_logger.exception(f'[{client}] requested [{b_msg}]')

    @property
    def key_extractor(self):
        return lambda id: self.peer_db.get(id, EMPTY_PEER).key

    def _handle_register(self, client, **kwargs):
        """Handle registration of the client

        Protocol: When a peer requests to be registered, an id and a key would
        be responded to him. the respond in unencrypted and with following keys:
            - status : "ok" if successful or "error" in case of an error
            - id     : a 4B integer representing the id of the peer. peer must 
                       keep this id for later requests.
            - secret  : 32B key to encrypt and decrypt massages
        """
        self.last_id += 1
        id = self.last_id
        key = generate_key()
        with self.peer_lock:
            self.peer_db[id] = Peer(id, client, key)
        self.logger.info(f'{client} registered as ID({id})')
        self.send_respond(id, client, False,
                          status="ok",
                          id=id,
                          secret=key.decode('ISO-8859-1'))

    def send_respond(self, _id, client, encrypted=True, **kwargs):
        """send response to the client"""
        self.sock.sendto(self.torrent.respond(
            encrypted,
            self.key_extractor(_id),
            **kwargs), client)

    def send_error(self, id, client, msg):
        """send error to the client"""
        self.send_respond(id, client, status="error", msg=msg)

    def add_file(self, id, client, name, checksum, size):
        """Adds a file to the DB"""
        file = TorFile(name, int(size), checksum)
        with self.file_lock:
            self.file_db[name] = file
            self.logger.info(f'[{name}] added by ID({id})')
            return file

    def add_provider(self,  id: int, client, file: TorFile, checksum=None):
        """Adds peer with id to filename providers

        If checksum is not None it will check checksum and if not matches will
        send an error to the client."""
        if checksum:
            file = self.file_db[file.name]
            if checksum != file.checksum:
                self.logger.warning(
                    f'ID({id}) does not added to [{file.name}] due to wrong checksum ({checksum})')
                self.send_error(id, client, f'checksums does not match')
                return
        with self.provider_lock:
            self.providers.add((file.name, id))
            self.send_respond(id, client,
                              status="ok",
                              secret=file.key.decode('ISO-8859-1'))
            self.logger.info(f'ID({id}) provides [{file.name}]')

    @check_missing(type=TR.SHARE)
    def _handle_share(self, client, **kwargs):
        """handle share request

        Protocol:
            1. If the file is shared for the first time the checksum and size is
               registered in the system.
            2. If file is shared before checksums must match to add the id to
               files provider.

        Args:
            client (tuple): ip, port of the sender
        """
        id = kwargs['id']
        filename = kwargs['filename']
        checksum = kwargs['checksum']
        file = self.file_db.get(filename, None)
        if file:
            self.add_provider(id, client, file, checksum)
        else:
            size = kwargs.get('size', None)
            if size == None:
                self.send_error(id, client,
                                msg="must provide size for new file.")
            else:
                file = self.add_file(id, client, filename, checksum, size)
                self.add_provider(id, client, file)


def load_config_file():
    parser = configparser.ConfigParser()
    read = parser.read(SERVER_CONFIG)
    if not read:
        raise FileNotFoundError(f'CONFIG FILE NOT FOUND')
    return dict(parser)


def get_parser():
    parser = argparse.ArgumentParser(
        prog='TorTracker',
        description="Simplified tracker of torrent network",
        epilog="Spring23 - CE40443 - Assignment 2")
    parser.add_argument('bind', nargs='?', metavar='ip:port',
                        help='IP and Port binding of the server',
                        type=ip_port_type)
    return parser


def load_config():
    config = load_config_file()
    parser = get_parser()
    args = parser.parse_args()
    if args.bind:
        ip, port = args.bind.split(':')
        config['NET']['Ip'] = ip
        config['NET']['Port'] = port
    return config


if __name__ == "__main__":
    conf = load_config()
    tracker = Tracker(conf)
    tracker.start_server()
