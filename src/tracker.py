import argparse
import configparser
import socket
import signal
import threading
import logging
import logging.config
import json
import time

from dataclasses import dataclass

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
        self.db_lock = threading.Lock()
        self.peer_lock = threading.Lock()
        self.id_lock = threading.Lock()
        self.torrent_db = {}
        self.torrent_peers = {}
        self.max_id = 1
        self.clients = {}

    def _init_logger(self, conf):
        logging.config.fileConfig(conf['SETTING']['LoggerConfig'])
        self.peer_logger = logging.getLogger('PEER')
        self.file_logger = logging.getLogger('FILE')

    @threaded
    def start_server(self):
        """Starts server in a new thread

        This will cause a non-blocking execution of the server. This is could be
        beneficial when we add console for the tracker."""
        self.start()

    def handle(self, b_msg: bytes, client):
        """Handles requests according to the protocol's RFC (!)"""
        msg = b_msg.decode()


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
                        help='IP and Port binding of the server')
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
