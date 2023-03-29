import argparse
import configparser
import socket
import signal
import threading
import logging
import logging.config
import json
import time

from enum import IntEnum
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


@dataclass
class File:
    name: str  # name of the file
    size: int  # size of the file
    uploader: tuple  # tuple of (ip, port)
    online_peers = []  # online peers of the file
    lock = threading.Lock()


@dataclass
class Peer:
    client: tuple
    shared_file: str
    requested_file: str  # if not None it is pending
    last_alive: float


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
        self.ttl = float(logging.config.fileConfig(conf['SETTING']['PTTL']))
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

    def alive_peer(self, client):
        peer = self.torrent_peers.get(client, None)
        # TODO: LOG
        if not peer:
            self.send(ASCII.NAK, client)
        else:
            peer.last_alive = time.time()
            self.send(ASCII.ACK, client)

    def log_status_remove(self, client, status: str):
        peer = self.torrent_peers.get(client, None)
        # TODO: LOG
        self.remove_peer(client)

    def not_interested(self, client):
        self.log_status_remove(client, 'NOT INTERESTED')

    def downloaded(self, client):
        self.log_status_remove(client, 'DOWNLOADED')

    def send(self, msg: str, client):
        self.sock.sendto(msg.encode(), client)

    def remove_dead_peer(self, file: File):
        now = time.time()
        alive = list(filter(lambda x: now - x.last_alive <
                     self.ttl * 2, file.online_peers))
        with file.lock:
            file.online_peers.clear()
            file.online_peers.extend(alive)

    def query(self, client, file):
        # TODO: log
        file = self.torrent_db.get(file, None)
        if file:
            self.add_to_pending(client, file)
            self.remove_dead_peer(file)
            with file.lock:
                self.send(json.dumps(file.online_peers), client)
        else:
            self.send(ASCII.NUL, client)

    def add_to_pending(self, client, file: File):
        peer = self.torrent_peers.get(client, None)
        if peer:
            self.clean_prev_activity(peer)
            peer.requested_file = file.name
        else:
            with self.peer_lock:
                self.torrent_peers[client] = Peer(client, None, file.name)

    def add_file(self, file, size, client):
        """Adds a file to database

        File will be added to the database with empty list of online peers.

        Args:
            file (str): name of the file
            size (int): in bytes
            client (tuple): ip port tuple

        Returns:
            File: created file
        """
        file = File(file, size, client)
        # TODO: log
        with self.db_lock:
            self.torrent_db[file] = file
        return file

    def add_peer(self, client, file: File):
        """Adds a peer to the system serving file

        adds a peer to the db and to file's online peers

        Args:
            client (tuple): (ip, port) tuple of the client
            file (File): file that peer serves

        Returns:
            Peer: peer object created
        """
        peer = Peer(client, file.name, None, time.time())
        # TODO: log
        with self.peer_lock:
            self.torrent_peers[client] = peer
        with file.lock:
            file.online_peers.append(client)
        return peer

    def discard_requested_file(self, peer: Peer):
        # TODO: Log
        pass

    def remove_peer(self, client):
        with self.peer_lock:
            return self.torrent_peers.pop(client, None)

    def clean_prev_activity(self, peer: Peer):
        if peer.requested_file:
            self.discard_requested_file(peer)
        elif peer.shared_file:
            file = self.torrent_db.get(peer.shared_file)
            self.remove_peer_from_file(file, peer.client)

    def join_peer(self, client, file, size):
        """Joins a client as a peer server of a file

        If file does not exist, It will create the file as a new file
        Args:
            client (tuple): (ip, port) tuple of the client
            file (str): name of the file
            size (int): size of the file in bytes
        """
        db_file = self.torrent_db.get(file, None)
        if not db_file:
            db_file = self.add_file(file, size, client)
        peer = self.torrent_peers.get(client, None)
        if peer:
            self.clean_prev_activity(peer)
        self.add_peer(client, db_file)
        self.send(ASCII.ACK, client)

    def remove_peer_from_file(self, file: File, client):
        with file.lock:
            try:
                file.online_peers.remove(client)
            except:
                pass

    def disconnect(self, client):
        """Removes client from peers and from file's online peers

        Args:
            client (tuple): ip, port
        """
        peer = self.remove_peer()
        if peer:
            file = self.torrent_db.get(peer.shared_file, None)
            if file:
                self.remove_peer_from_file(file, client)
        # TODO: LOG

    def protocol_error(self, client):
        pass

    def handle(self, msg: bytes, client):
        """Handles requests according to the protocol's RFC (!)"""
        msg = msg.decode()
        if len(msg) == 0:
            self.alive_peer(client)
        elif msg.startswith(ASCII.ACK):
            filename, size = msg[1:].strip().split(':')
            self.join_peer(client, filename, int(size))
        elif msg.startswith(ASCII.SYN):
            self.downloaded(client)
        elif msg.startswith(ASCII.NAK):
            self.not_interested(client)
        elif msg.startswith(ASCII.ENQ):
            self.query(client, msg[1:])
        elif msg.startswith(ASCII.NUL):
            self.disconnect(client)
        else:
            self.protocol_error(client)


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
    parser.add_argument('IP:Port', nargs='?',
                        help='IP and Port binding of the server')
    return parser


def load_config():
    config = load_config_file()
    parser = get_parser()
    args = parser.parse_args()
    if getattr(args, 'IP:Port'):
        ip, port = getattr(args, 'IP:Port').split(':')
        config['NET']['Ip'] = ip
        config['NET']['Port'] = port
    return config


if __name__ == "__main__":
    conf = load_config()
    tracker = Tracker(conf)
