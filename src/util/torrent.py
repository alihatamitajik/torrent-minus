from enum import IntEnum, auto
import json


class TorrentRequest(IntEnum):
    REGISTER = auto()

    def __str__(self) -> str:
        return self.name.lower()


class TorrentProtocol:
    def read_req(self, msg: bytes, get_key=None):
        """Reeds message in the protocol and returns its fields

        get_key(id) returns a key string to decrypt the message. it's not
        used in register massage."""
        if msg == b'\x00register':
            return TorrentRequest.REGISTER, {}

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
            pass

    def req(self, type: TorrentRequest, **kwargs) -> bytes:
        """Prepare bytes to be sent in the protocol"""
        return getattr(self, f"_req_{type}")(**kwargs)

    def _req_register(self, **kwargs) -> bytes:
        """register massage

        Protocol: For registering, peer must send a UTP packet to the tracker
        that contains no-encryption byte followed by text register.
        """
        return b'\x00register'

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
            pass
        else:
            return f'\x00{json.dumps(kwargs)}'.encode()
