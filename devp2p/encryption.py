#!/usr/bin/python

from crypto import privtopub, mk_privkey
from crypto import sha3
from crypto import ECCx
from crypto import ecdsa_recover
import pyelliptic
from utils import idec  # integer decode
from utils import ienc  # integer encode


def sxor(s1, s2):
    "string xor"
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


class Transport(object):

    def __init__(self, sender, receiver):
        assert isinstance(sender, Peer)
        assert isinstance(receiver, Peer)
        self.sender = sender
        self.receiver = receiver

    def send(self, data):
        self.receiver.receive(data)

    def receive(self, data):
        self.sender.receive(data)


class Peer(object):

    "Peer carries the session with a connected remote node"

    def __init__(self, local_node, transport=None, receive_cb=None):
        self.local_node = local_node
        self.transport = transport
        self.session = None
        self.receive_cb = receive_cb

    def connect(self, remote_node):
        self.session = RLPxSession(self)
        self.session.send_authentication(remote_node)

    def send(self, data):
        assert self.session
        assert self.transport
        self.transport.send(self.session.encode(data))

    def receive(self, data):
        if not self.session:
            self.session = RLPxSession(self)
            self.session.respond_authentication(data)
        else:
            data = self.session.decode(data)
        if self.receive_cb:
            self.receive_cb(self, data)


class LocalNode(object):

    def __init__(self, pubkey, privkey):
        self.ecc = ECCx(pubkey=pubkey, privkey=privkey)

    @property
    def pubkey(self):
        return self.ecc.pubkey_x + self.ecc.pubkey_y

    def sign(self, data):
        return self.ecc.sign(data)


class RemoteNode(object):

    def __init__(self, pubkey):
        self.pubkey = pubkey
        self.token = None


class RLPxSession(object):

    ephemeral_ecc = None
    nonce = None
    token = None
    aes_secret = None
    aes_enc = None
    aes_dec = None
    egress_mac = None
    ingress_mac = None
    remote_node = None
    _authentication_sent = False
    is_ready = False

    def __init__(self, peer):
        # persisted peer data. keys are the nodeid
        # session data
        self.peer = peer

    def __repr__(self):
        return '<RLPxSession (%s)>' % self.address.encode('hex')

    @property
    def node(self):
        return self.peer.local_node

    def encrypt(self, header, frame):
        """
        header-mac: right128 of
        egress-mac.update(aes(mac-secret,egress-mac)^header-ciphertext)
        """
        assert self.is_ready is True

        def aes(data):
            return self.aes_enc.update(data)

        def mac(data):
            return self.egress_mac.update(data)

        # header
        assert len(header) == 16  # zero padded to 16 bytes
        header_ciphertext = aes(header)
        assert len(header_ciphertext) <= 32  # must not be larger than mac
        # FIXME mac-secret!?
        header_mac = mac(sxor(aes(mac('')), header_ciphertext))[-16:]
        # frame
        frame_ciphertext = aes(frame)
        frame_mac = self.egress_mac.update(frame_ciphertext)
        return header_ciphertext + header_mac + frame_ciphertext + frame_mac

    def decrypt(self, data):
        assert self.is_ready is True

        def aes(data):
            return self.aes_dec.update(data)

        def mac(data):
            return self.egress_mac.update(data)

        header_ciphertext = data[:16]
        header_mac = data[16:32]

        header = aes(header_ciphertext)
        expected_header_mac = mac(sxor(aes(mac(''), header_ciphertext)))[-16:]
        assert expected_header_mac == header_mac

        # FIXME check frame length in header
        # assume datalen == framelen for now
        frame_mac = self.egress_mac.update(frame_ciphertext)
        data = aes(data[32:])

    def send_authentication(self, remote_node):
        """
        1. initiator generates ecdhe-random and nonce and creates auth
        2. initiator connects to remote and sends auth

        Handshake for connecting to Known Peer
        eciesEncrypt(remote-pubk, sign(privkey, token^nonce) || 0x80 || ecdhe-random || nonce )

        Handshake for connecting to New Peer
        eciesEncrypt(remote-pubk, sign(privkey, nonce) || 0x80 || ecdhe-random || nonce )

        The value 0x80 is a placeholder which maybe used in the future for versioning and/or
        protocol handshake.
        """
        self.ephemeral_ecc = ECCx()  # FIXME, add seed
        ecdhe_pubkey = self.ephemeral_ecc.get_pubkey()
        assert len(ecdhe_pubkey) == 512 / 8
        token = remote_node.token
        nonce = ienc(random.randint(0, 2 ** 256 - 1))
        assert len(nonce) == 32
        token_or_nonce = token or nonce
        signature = self.node.sign(ienc(token_or_nonce))
        assert len(signature) == 65
        payload = signature + '0x80' + ecdhe_pubkey + token_or_nonce
        auth_message = crypto.encrypt(payload, remote.pubkey)
        self.peer.send(auth_message)
        self._authentication_sent = True

    def receive_authentication(self, other, ciphertext):
        """
        Verification (function, upon receive of PresetAuthentication):
        3. remote generates ecdhe-random and nonce and creates auth
        4. remote receives auth and decrypts (ECIES performs authentication before
        decryption)
            - If address is known, lookup token and public key to be authenticated
            - derive signature-message = sha3(token || addr^addrRemote)
            - success -> AcknowledgeAuthentication
        5. remote sends auth
        6. remote derives shared-secret, aes-secret, mac-secret, ingress-mac, egress-mac
"""

        # eciesEncrypt(remote-pubk, sign(privkey, token^nonce) || 0x80 || ecdhe-random || nonce )

        data = self.node.decrypt(ciphertext)
        assert len(data) == 64 + 1 + 64 + 32
        signature = data[:65]
        assert data[65] == '0x80'
        remote_ecdhe_pubkey = data[65:65 + 64]
        token_or_nonce = idec(data[-32:])

        # verify signature
        if not self.node.verify(signature, token_or_nonce):
            return self.disconnect()

        # recover remote pubkey
        remote_pubkey = ecdsa_recover(token_or_nonce, signature)

        # lookup pubkey and related token
        token_database = dict()  # FIXME
        token = token_database.get(remote_pubkey, None)
        if token and token != token_or_nonce:
            # something fishy
            # FIXME reset node reputation
            pass

        remote_nonce = token_or_nonce

        # send authentication if not yet
        if not self._authentication_sent:
            remote_node = RemoteNode(remote_pubkey)  # FIXME LOOKUP
            self.send_authentication(remote_node)

            # - success -> AcknowledgeAuthentication
            self.acknowledge_authentication(other, remote_pubkey, remote_ecdhe_pubkey)

        # ecdhe_shared_secret = ecdh.agree(ecdhe-random, ecdhe-random-public)
        # Compute public key with the local private key and return a 512bits shared key
        ecdhe_shared_secret = self.ephemeral_ecc.get_ecdh_key(remote_pubkey)
        ecdhe_pubkey = ephemeral_ecc.get_pubkey()
        # shared-secret = sha3(ecdhe-shared-secret || sha3(nonce || remote-nonce))
        shared_secret = sha3(ecdhe_shared_secret + sha3(ienc(self.nonce) + ienc(remote_nonce)))

        self.aes_secret = sha3_256(ecdhe_shared_secret + shared_secret)
        self.mac_secret = sha3_256(ecdhe_shared_secret + self.aes_secret)
        # egress-mac = sha3(mac-secret^nonce || auth)
        self.egress_mac = sha3_256(sxor(self.mac_secret, self.nonce) + ciphertext)
        # ingress-mac = sha3(mac-secret^remote-nonce || auth)
        self.ingress_mac = sha3_256(sxor(self.mac_secret, remote_nonce) + ciphertext)
        self.token = sha3(shared_secret)

        iv = pyelliptic.Cipher.gen_IV('aes-256-ctr')
        self.aes_enc = pyelliptic.Cipher(self.aes_secret, iv, 1, ciphername='aes-256-ctr')
        self.aes_dec = pyelliptic.Cipher(self.aes_secret, iv, 0, ciphername='aes-256-ctr')

        self.is_ready = True


def main():
    alice_privkey = mk_privkey('secret1')
    alice_pubkey = privtopub(alice_privkey)
    print len(alice_pubkey), type(alice_pubkey)
    alice = LocalNode(alice_pubkey, alice_privkey)

    bob_privkey = mk_privkey('secret2')
    bob_pubkey = privtopub(bob_privkey)
    bob = LocalNode(bob_pubkey, bob_privkey)

    def _receivecb(peer, data):
        print peer, data

    # alice knows bob and connects
    node_bob = RemoteNode(bob_pubkey)
    peer_alice = Peer(alice, transport=None, receive_cb=_receivecb)
    peer_bob = Peer(bob, transport=None, receive_cb=_receivecb)
    peer_alice.transport = Transport(sender=peer_alice, receiver=peer_bob)
    peer_bob.transport = Transport(sender=peer_bob, receiver=peer_alice)

    peer_alice.connect(peer_bob)


if __name__ == '__main__':
    main()
