#!/usr/bin/env python
import random
import struct
from devp2p.crypto import sha3
from sha3 import sha3_256
from devp2p.crypto import ECCx
from devp2p.crypto import ecdsa_recover
from devp2p.crypto import ecdsa_verify
import pyelliptic
# from devp2p.utils import idec  # integer decode
from devp2p.utils import ienc  # integer encode
import Crypto.Cipher.AES as AES


def sxor(s1, s2):
    "string xor"
    assert len(s1) == len(s2)
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

    def __init__(self, privkey):
        self.ecc = ECCx(raw_privkey=privkey)

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
    remote_ephemeral_pubkey = None
    initiator_nonce = None
    responder_nonce = None
    auth_init = None
    auth_ack = None
    token = None
    aes_secret = None
    aes_enc = None
    aes_dec = None
    mac_enc = None
    egress_mac = None
    ingress_mac = None
    _authentication_sent = False
    is_ready = False
    remote_token_found = False
    remote_pubkey = None

    def __init__(self, ecc, is_initiator=False, ephemeral_privkey=None):
        self.ecc = ecc
        self.is_initiator = is_initiator
        self.ephemeral_ecc = ECCx(raw_privkey=ephemeral_privkey)

    def __repr__(self):
        return '<RLPxSession (%s)>' % self.address.encode('hex')

    def encrypt(self, header, frame):
        """
        # https://github.com/ethereum/go-ethereum/blob/develop/p2p/rlpx.go
        # https://github.com/ethereum/cpp-ethereum/blob/develop/libp2p/RLPxFrameIO.cpp
        """
        assert self.is_ready is True

        def aes(data=''):
            return self.aes_enc.update(data)

        def mac(data=''):
            self.egress_mac.update(data)
            return self.egress_mac.digest()

        # header
        assert len(header) == 16  # zero padded to 16 bytes
        header_ciphertext = aes(header)
        assert len(header_ciphertext) == 16
        # egress-mac.update(aes(mac-secret,egress-mac) ^ header-ciphertext).digest
        header_mac = mac(sxor(self.mac_enc(mac()[:16]), header_ciphertext))[:16]

        # frame

        if len(frame) % 16:  # padding
            frame += '\x00' * (16 - len(frame) % 16)

        frame_ciphertext = aes(frame)
        assert len(frame_ciphertext) == len(frame)
        # egress-mac.update(aes(mac-secret,egress-mac) ^
        # left128(egress-mac.update(frame-ciphertext).digest))
        fmac_seed = mac(frame_ciphertext)
        frame_mac = mac(sxor(self.mac_enc(mac()[:16]), fmac_seed[:16]))[:16]

        return header_ciphertext + header_mac + frame_ciphertext + frame_mac

    def decrypt(self, data):
        assert self.is_ready is True

        def aes(data=''):
            return self.aes_dec.update(data)

        def mac(data=''):
            self.ingress_mac.update(data)
            return self.ingress_mac.digest()

        header_ciphertext = data[:16]
        header_mac = data[16:32]

        # ingress-mac.update(aes(mac-secret,ingress-mac) ^ header-ciphertext).digest
        expected_header_mac = mac(sxor(self.mac_enc(mac()[:16]), header_ciphertext))[:16]
        # expected_header_mac = self.updateMAC(self.ingress_mac, header_ciphertext)
        assert expected_header_mac == header_mac
        header = aes(header_ciphertext)

        frame_size = struct.unpack('>I', '\x00' + header[:3])[0]
        assert frame_size <= len(data) - 32
        read_size = frame_size
        if read_size % 16:
            read_size += 16 - read_size % 16
        assert read_size == len(data) - 32 - 16

        # FIXME check frame length in header
        # assume datalen == framelen for now
        frame_ciphertext = data[32:-16]
        assert frame_ciphertext == data[32:32 + read_size]
        frame_mac = data[-16:]
        assert frame_mac == data[32 + read_size:]
        assert len(frame_mac) == 16

        # ingres-mac.update(aes(mac-secret,ingres-mac) ^
        # left128(ingres-mac.update(frame-ciphertext).digest))
        fmac_seed = mac(frame_ciphertext)
        expected_frame_mac = mac(sxor(self.mac_enc(mac()[:16]), fmac_seed[:16]))[:16]
        assert frame_mac == expected_frame_mac

        frame = aes(frame_ciphertext)[:frame_size]
        return dict(header=header, frame=frame)

    def create_auth_message(self, remote_pubkey, token=None, ephemeral_privkey=None, nonce=None):
        """
        1. initiator generates ecdhe-random and nonce and creates auth
        2. initiator connects to remote and sends auth

        New:
        E(remote-pubk,
            S(ephemeral-privk, ecdh-shared-secret ^ nonce) ||
            H(ephemeral-pubk) || pubk || nonce || 0x0
        )
        Known:
        E(remote-pubk,
            S(ephemeral-privk, token ^ nonce) || H(ephemeral-pubk) || pubk || nonce || 0x1)
        """
        assert self.is_initiator

        self.remote_pubkey = remote_pubkey

        if not token:  # new
            ecdh_shared_secret = self.ecc.get_ecdh_key(remote_pubkey)
            token = ecdh_shared_secret
            flag = 0x0
        else:
            flag = 0x1

        self.initiator_nonce = nonce or sha3(ienc(random.randint(0, 2 ** 256 - 1)))
        assert len(self.initiator_nonce) == 32

        token_xor_nonce = sxor(token, self.initiator_nonce)
        assert len(token_xor_nonce) == 32

        ephemeral_pubkey = self.ephemeral_ecc.raw_pubkey

        assert len(ephemeral_pubkey) == 512 / 8
        # S(ephemeral-privk, ecdh-shared-secret ^ nonce)
        S = self.ephemeral_ecc.sign(token_xor_nonce)
        assert len(S) == 65

        # S || H(ephemeral-pubk) || pubk || nonce || 0x0
        auth_message = S + sha3(ephemeral_pubkey) + self.ecc.raw_pubkey + \
            self.initiator_nonce + chr(flag)
        assert len(auth_message) == 65 + 32 + 64 + 32 + 1 == 194
        return auth_message

    def encrypt_auth_message(self, auth_message, remote_pubkey):
        assert self.is_initiator
        self.auth_init = self.ecc.ecies_encrypt(auth_message, remote_pubkey)
        return self.auth_init

    def encrypt_auth_ack_message(self, auth_message, remote_pubkey):
        assert not self.is_initiator
        self.auth_ack = self.ecc.ecies_encrypt(auth_message, remote_pubkey)
        return self.auth_ack

    def send_authentication(self, remote_node, ephermal_privkey=None):
        auth_message = self.create_auth_message(remote_node, ephermal_privkey)
        self.peer.send(auth_message)
        self._authentication_sent = True

    def receive_authentication(self, ciphertext):
        assert not self.is_initiator
        self.decode_authentication(ciphertext)

    def decode_authentication(self, ciphertext, get_token_cb=None):
        """
        3. optionally, remote decrypts and verifies auth
            (checks that recovery of signature == H(ephemeral-pubk))
        4. remote generates authAck from remote-ephemeral-pubk and nonce
            (authAck = authRecipient handshake)

        optional: remote derives secrets and preemptively sends protocol-handshake (steps 9,11,8,10)
        """
        assert not self.is_initiator

        self.auth_init = ciphertext
        auth_message = self.ecc.ecies_decrypt(ciphertext)
        # S || H(ephemeral-pubk) || pubk || nonce || 0x[0|1]
        assert len(auth_message) == 65 + 32 + 64 + 32 + 1 == 194
        signature = auth_message[:65]
        H_initiator_ephemeral_pubkey = auth_message[65:65 + 32]
        initiator_pubkey = auth_message[65 + 32:65 + 32 + 64]
        self.remote_pubkey = initiator_pubkey
        self.initiator_nonce = auth_message[65 + 32 + 64:65 + 32 + 64 + 32]
        known_flag = bool(ord(auth_message[65 + 32 + 64 + 32:]))

        # token or new ecdh_shared_secret
        if known_flag:
            self.remote_token_found = True
            # hat todo if remote has token, but local forgot it?
            token = get_token_cb(initiator_pubkey)
            assert token
        else:
            token = ecdh_shared_secret = self.ecc.get_ecdh_key(initiator_pubkey)  # ???

        # verify auth
        # S(ephemeral-privk, ecdh-shared-secret ^ nonce)
        ecdh_shared_secret = self.ecc.get_ecdh_key(initiator_pubkey)
        signed = sxor(ecdh_shared_secret, self.initiator_nonce)

        # recover initiator ephemeral pubkey
        self.remote_ephemeral_pubkey = ecdsa_recover(signed, signature)

        assert ecdsa_verify(self.remote_ephemeral_pubkey, signature, signed)

        # checks that recovery of signature == H(ephemeral-pubk)
        assert H_initiator_ephemeral_pubkey == sha3(self.remote_ephemeral_pubkey)

    def create_auth_ack_message(self, ephemeral_pubkey=None, nonce=None, token_found=False):
        """
        authRecipient = E(remote-pubk, remote-ephemeral-pubk || nonce || 0x1) // token found
        authRecipient = E(remote-pubk, remote-ephemeral-pubk || nonce || 0x0) // token not found

        nonce and empehemeral-pubk are local!
        """
        assert not self.is_initiator
        ephemeral_pubkey = ephemeral_pubkey or self.ephemeral_ecc.raw_pubkey
        self.responder_nonce = nonce or sha3(ienc(random.randint(0, 2 ** 256 - 1)))

        flag = chr(1 if token_found else 0)
        msg = ephemeral_pubkey + self.responder_nonce + flag
        assert len(msg) == 64 + 32 + 1 == 97
        return msg

    def decode_auth_ack_message(self, ciphertext):
        assert self.is_initiator
        self.auth_ack = ciphertext
        auth_ack_message = self.ecc.ecies_decrypt(ciphertext)
        assert len(auth_ack_message) == 64 + 32 + 1
        self.remote_ephemeral_pubkey = auth_ack_message[:64]
        self.responder_nonce = auth_ack_message[64:64 + 32]
        self.remote_token_found = bool(ord(auth_ack_message[-1]))

    def setup_cipher(self):
        # https://github.com/ethereum/cpp-ethereum/blob/develop/libp2p/RLPxFrameIO.cpp#L34
        assert self.responder_nonce
        assert self.initiator_nonce
        assert self.auth_init
        assert self.auth_ack
        assert self.remote_ephemeral_pubkey

        # derive base secrets from ephemeral key agreement
        # ecdhe-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        ecdhe_shared_secret = self.ephemeral_ecc.get_ecdh_key(self.remote_ephemeral_pubkey)

        # shared-secret = sha3(ecdhe-shared-secret || sha3(nonce || initiator-nonce))
        shared_secret = sha3(
            ecdhe_shared_secret + sha3(self.responder_nonce + self.initiator_nonce))

        self.ecdhe_shared_secret = ecdhe_shared_secret  # FIXME DEBUG
        self.shared_secret = shared_secret   # FIXME DEBUG

        # token = sha3(shared-secret)
        self.token = sha3(shared_secret)

        # aes-secret = sha3(ecdhe-shared-secret || shared-secret)
        self.aes_secret = sha3(ecdhe_shared_secret + shared_secret)

        # mac-secret = sha3(ecdhe-shared-secret || aes-secret)
        self.mac_secret = sha3(ecdhe_shared_secret + self.aes_secret)

        # setup sha3 instances for the MACs
        # egress-mac = sha3.update(mac-secret ^ recipient-nonce || auth-sent-init)
        mac1 = sha3_256(sxor(self.mac_secret, self.responder_nonce) + self.auth_init)
        # ingress-mac = sha3.update(mac-secret ^ initiator-nonce || auth-recvd-ack)
        mac2 = sha3_256(sxor(self.mac_secret, self.initiator_nonce) + self.auth_ack)

        if self.is_initiator:
            self.egress_mac, self.ingress_mac = mac1, mac2
        else:
            self.egress_mac, self.ingress_mac = mac2, mac1

        ciphername = 'aes-256-ctr'
        iv = "\x00" * 16
        assert len(iv) == 16
        self.aes_enc = pyelliptic.Cipher(self.aes_secret, iv, 1, ciphername=ciphername)
        self.aes_dec = pyelliptic.Cipher(self.aes_secret, iv, 0, ciphername=ciphername)
        self.mac_enc = AES.AESCipher(self.mac_secret, AES.MODE_ECB).encrypt

        self.is_ready = True

    def something():
        ##################

        # send authentication if not yet
        if not self._authentication_sent:
            remote_node = RemoteNode(remote_pubkey)  # FIXME LOOKUP
            self.send_authentication(remote_node)

            # - success -> AcknowledgeAuthentication
            self.acknowledge_authentication(other, remote_pubkey, remote_ecdhe_pubkey)


def main():
    from crypto import privtopub, mk_privkey
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
