from enum import IntEnum, auto
from functools import wraps
from .encrypt import encrypt, decrypt
import json
from io import BufferedReader


class TorrentRequest(IntEnum):
    REGISTER = auto()
    SHARE = auto()
    ALIVE = auto()
    QUERY = auto()
    DOWNLOAD = auto()
    REMOVE = auto()
    DOWNLOADED = auto()
    FAILED = auto()

    def __str__(self) -> str:
        return self.name.lower()


def encrypted_peer(fn):
    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        """returns encrypted value of that function

        Protocol: requests should be made with a byte 1 in the beginning
        followed by 4 byte id followed by encrypted massage (by the key provided
        by tracker when registering and method Salsa20).

        Id byte-order is big endian.
        """
        if not kwargs.get('key', None):
            raise KeyError('secret key is not specified')
        if not kwargs.get('id', None):
            raise KeyError('id not specified')
        key = kwargs.pop('key')
        id = int(kwargs.pop('id'))
        return b'\x01' + id.to_bytes(4, 'big') + encrypt(fn(self, *args, **kwargs), key)
    return wrapper


class TorrentProtocol:
    FIELDS = {
        TorrentRequest.SHARE: {'must': ['filename', 'checksum'],
                               'may':  ['size']},
        TorrentRequest.ALIVE: {'must': [], 'may': []},
        TorrentRequest.QUERY: {'must': ['filename'], 'may': []},
        TorrentRequest.REMOVE: {'must': ['filename'], 'may': []},
        TorrentRequest.DOWNLOADED: {'must': ['filename', 'checksum'],
                                    'may':  ['']},
        TorrentRequest.FAILED: {'must': ['filename', 'provider'],
                                'may':  ['']},
    }

    def missing_fields(self, r_type: TorrentRequest, attrs: dict, must_may=False):
        """returns missing fields from the request"""
        missing = []
        keys = TorrentProtocol.FIELDS[r_type]['must'].copy()
        if must_may:
            keys.extend(TorrentProtocol.FIELDS[r_type]['may'])
        for key in keys:
            if key not in attrs:
                missing.append(key)
        return missing

    def read_req(self, msg: bytes, get_key=None):
        """Reeds message in the protocol and returns its fields

        get_key(id) returns a key string to decrypt the message. it's not
        used in register massage."""
        if msg == b'\x00register':
            return TorrentRequest.REGISTER, {}
        else:
            if msg[0]:
                id = int.from_bytes(msg[1:5], 'big')
                key = get_key(id)
                attrs = json.loads(decrypt(msg[5:], key))
                r_type = TorrentRequest(attrs.pop('type'))
                attrs['id'] = id
                return r_type, attrs

    def read_response(self, msg: bytes, key=None) -> dict:
        """read a response massage

        responses are json formatted. they might be encrypted or not. If they
        are encrypted (i.e. first byte is 1) then rest of the bytes will be
        decrypted and return json string.

        this method may raise an error if the decrypted string is not a valid
        JSON string."""
        if not msg[0]:
            return json.loads(msg[1:])
        else:
            return json.loads(decrypt(msg[1:], key))

    def req(self, t_type: TorrentRequest, **kwargs) -> bytes:
        """Prepare bytes to be sent in the protocol"""
        if t_type == TorrentRequest.REGISTER:
            return self._req_register()
        else:
            return self._req_json(type=t_type.value, **kwargs)

    def _req_register(self) -> bytes:
        """register massage

        Protocol: For registering, peer must send a UTP packet to the tracker
        that contains no-encryption byte followed by text register.
        """
        return b'\x00register'

    @encrypted_peer
    def _req_json(self, **kwargs):
        """sends an encrypted json of kwargs

        Protocol: requests should be sent in JSON format (weather its encrypted
        or not) except for the register request. Request should have following
        attributes:
            - type  : an integer number corresponding to the type of the request
                      listed in TorrentRequest.
        other attributes should be added to the json as they are needed with the
        request (e.g. share request needs "filename", "size" and "checksum").              
        """
        return json.dumps(kwargs).encode()

    def respond(self, encrypted: bool = False, key=None, **kwargs) -> bytes:
        """respond massage

        Protocol: responses are in JSON format. They might be encrypted (first
        byte is 1) or in plain text (first byte is 0).

        This method will raise an error if it is encrypted but no key is
        provided.
        """
        if encrypted and not key:
            raise KeyError('key not provided!')
        if encrypted:
            return b'\x01' + encrypt(json.dumps(kwargs).encode(), key)
        else:
            return f'\x00{json.dumps(kwargs)}'.encode()
