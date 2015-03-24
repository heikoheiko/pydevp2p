#!/usr/bin/env python
import random
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
    auth_sent_init = None
    auth_recvd_ack = None
    auth_sent_ack = None
    auth_recvd_init = None
    token = None
    aes_secret = None
    aes_enc = None
    aes_dec = None
    mac_enc = None
    egress_mac = None
    ingress_mac = None
    remote_node = None
    _authentication_sent = False
    is_ready = False
    is_initiator = False

    session_states = (None, 'auth_sent', 'auth_received', 'ready')
    session_roles = ('initiator', 'responder')

    def __init__(self, peer=None, ephemeral_privkey=None):
        # persisted peer data. keys are the nodeid
        # session data
        self.peer = peer
        if peer:
            self.node = peer.local_node.ecc
        else:
            self.node = None
        self.session_state = None
        self.ephemeral_ecc = ECCx(raw_privkey=ephemeral_privkey)

    def __repr__(self):
        return '<RLPxSession (%s)>' % self.address.encode('hex')

    def encrypt(self, header, frame):
        """
        # https://github.com/ethereum/go-ethereum/blob/develop/p2p/rlpx.go#L156
        # https://github.com/ethereum/cpp-ethereum/blob/f9a0fdda39af29564ed108767c7c0ffd94d61c2d/libp2p/RLPxFrameIO.cpp#L190
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
        frame_ciphertext = aes(frame)
        assert len(frame_ciphertext) == len(frame)
        # egress-mac.update(aes(mac-secret,egress-mac) ^ left128(egress-mac.update(frame-ciphertext).digest))
        current_digest = mac()
        frame_mac = mac(sxor(self.mac_enc(current_digest[:16]), mac(frame_ciphertext)[:16]))[:16]
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
        assert expected_header_mac == header_mac
        header = aes(header_ciphertext)

        # FIXME check frame length in header
        # assume datalen == framelen for now
        frame_ciphertext = data[32:-16]
        frame_mac = data[-16:]
        # ingres-mac.update(aes(mac-secret,ingres-mac) ^ left128(ingres-mac.update(frame-ciphertext).digest))
        current_digest = mac()
        expected_frame_mac = mac(
            sxor(self.mac_enc(current_digest[:16]), mac(frame_ciphertext)[:16]))[:16]
        assert frame_mac == expected_frame_mac

        frame = aes(frame_ciphertext)
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

        if not token:  # new
            ecdh_shared_secret = self.node.get_ecdh_key(remote_pubkey)
            token = ecdh_shared_secret
            flag = 0x0
        else:
            flag = 0x1

        self.initiator_nonce = nonce or ienc(random.randint(0, 2 ** 256 - 1))
        assert len(self.initiator_nonce) == 32

        token_xor_nonce = sxor(token, self.initiator_nonce)
        assert len(token_xor_nonce) == 32

        # generate session ephemeral key
        if not ephemeral_privkey:
            ephemeral_privkey = sha3(ienc(random.randint(0, 2 ** 256 - 1)))

        ephemeral_pubkey = self.ephemeral_ecc.raw_pubkey

        assert len(ephemeral_pubkey) == 512 / 8
        # S(ephemeral-privk, ecdh-shared-secret ^ nonce)
        S = self.ephemeral_ecc.sign(token_xor_nonce)
        assert len(S) == 65

        # S || H(ephemeral-pubk) || pubk || nonce || 0x0
        auth_message = S + sha3(ephemeral_pubkey) + self.node.raw_pubkey + \
            self.initiator_nonce + chr(flag)
        assert len(auth_message) == 65 + 32 + 64 + 32 + 1 == 194
        return auth_message

    def encrypt_auth_message(self, auth_message, remote_pubkey):
        self.auth_sent_init = self.node.ecies_encrypt(auth_message, remote_pubkey)
        return self.auth_sent_init

    def encrypt_auth_ack_message(self, auth_message, remote_pubkey):
        self.auth_sent_ack = self.node.ecies_encrypt(auth_message, remote_pubkey)
        return self.auth_sent_ack

    def send_authentication(self, remote_node, ephermal_privkey=None):
        self.is_initiator = True
        auth_message = self.create_auth_message(remote_node, ephermal_privkey)
        self.peer.send(auth_message)
        self._authentication_sent = True

    def receive_authentication(self, ciphertext):
        self.decode_authentication(ciphertext)

    def decode_authentication(self, ciphertext):
        """
        3. optionally, remote decrypts and verifies auth
            (checks that recovery of signature == H(ephemeral-pubk))
        4. remote generates authAck from remote-ephemeral-pubk and nonce
            (authAck = authRecipient handshake)

        optional: remote derives secrets and preemptively sends protocol-handshake (steps 9,11,8,10)
        """
        self.auth_recvd_init = ciphertext
        auth_message = self.node.ecies_decrypt(ciphertext)
        # S || H(ephemeral-pubk) || pubk || nonce || 0x[0|1]
        assert len(auth_message) == 65 + 32 + 64 + 32 + 1 == 194
        signature = auth_message[:65]
        H_initiator_ephemeral_pubkey = auth_message[65:65 + 32]
        initiator_pubkey = auth_message[65 + 32:65 + 32 + 64]
        self.initiator_nonce = auth_message[65 + 32 + 64:65 + 32 + 64 + 32]
        known_flag = auth_message[65 + 32 + 64 + 32:]

        # token or new ecdh_shared_secret
        token_database = dict()  # FIXME
        token_found = False
        if known_flag == 1:
            token = token_database.get(initiator_pubkey)
            if token:
                token_found = True
        else:
            token = ecdh_shared_secret = self.node.get_ecdh_key(initiator_pubkey)  # ???

        # verify auth
        # S(ephemeral-privk, ecdh-shared-secret ^ nonce)
        ecdh_shared_secret = self.node.get_ecdh_key(initiator_pubkey)
        signed = sxor(ecdh_shared_secret, self.initiator_nonce)

        # recover initiator ephemeral pubkey
        self.initiator_ephemeral_pubkey = ecdsa_recover(signed, signature)

        assert ecdsa_verify(self.initiator_ephemeral_pubkey, signature, signed)

        # checks that recovery of signature == H(ephemeral-pubk)
        assert H_initiator_ephemeral_pubkey == sha3(self.initiator_ephemeral_pubkey)

        return dict(initiator_ephemeral_pubkey=self.initiator_ephemeral_pubkey,
                    token=token,
                    token_found=token_found,
                    ecdh_shared_secret=ecdh_shared_secret,
                    initiator_pubkey=initiator_pubkey,
                    nonce=self.initiator_nonce,
                    known_flag=known_flag
                    )

    def create_auth_ack_message(self, remote_ephemeral_pubkey, nonce, token_found=False):
        """
        authRecipient = E(remote-pubk, remote-ephemeral-pubk || nonce || 0x1) // token found
        authRecipient = E(remote-pubk, remote-ephemeral-pubk || nonce || 0x0) // token not found

        nonce and empehemeral-pubk are local!
        """
        self.responder_nonce = nonce  # FIXME
        flag = chr(1 if token_found else 0)
        msg = remote_ephemeral_pubkey + nonce + flag
        assert len(msg) == 64 + 32 + 1 == 97
        return msg

    def decode_auth_ack_message(self, ciphertext):
        self.auth_recvd_ack = ciphertext
        auth_ack_message = self.node.ecies_decrypt(ciphertext)
        assert len(auth_ack_message) == 64 + 32 + 1
        self.responder_ephemeral_pubkey = auth_ack_message[:64]
        self.responder_nonce = auth_ack_message[64:64 + 32]
        token_found_flag = ord(auth_ack_message[-1])

    def setup_cipher(self):

        # ecdhe-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        if self.is_initiator:
            other_pub = self.responder_ephemeral_pubkey
        else:
            other_pub = self.initiator_ephemeral_pubkey

        ecdhe_shared_secret = self.ephemeral_ecc.get_ecdh_key(other_pub)

        # shared-secret = sha3(ecdhe-shared-secret || sha3(initiator-nonce || remote-nonce))
        shared_secret = sha3(
            ecdhe_shared_secret + sha3(self.initiator_nonce + self.responder_nonce))

        self.ecdhe_shared_secret = ecdhe_shared_secret  # FIXME DEBUG
        self.shared_secret = shared_secret   # FIXME DEBUG

        # token = sha3(shared-secret)
        self.token = sha3(shared_secret)

        # aes-secret = sha3(ecdhe-shared-secret || shared-secret)
        self.aes_secret = sha3(ecdhe_shared_secret + shared_secret)

        # mac-secret = sha3(ecdhe-shared-secret || aes-secret)
        self.mac_secret = sha3(ecdhe_shared_secret + self.aes_secret)

        if self.is_initiator:
            # egress-mac = sha3.update(mac-secret ^ recipient-nonce || auth-sent-init)
            self.egress_mac = sha3_256(
                sxor(self.mac_secret, self.responder_nonce) + self.auth_sent_init)
            # ingress-mac = sha3.update(mac-secret ^ initiator-nonce || auth-recvd-ack)
            self.ingress_mac = sha3_256(
                sxor(self.mac_secret, self.initiator_nonce) + self.auth_recvd_ack)
        else:
            # egress-mac = sha3.update(mac-secret ^ initiator-nonce || auth-sent-ack)
            self.egress_mac = sha3_256(
                sxor(self.mac_secret, self.initiator_nonce) + self.auth_sent_ack)
            # ingress-mac = sha3.update(mac-secret ^ recipient-nonce || auth-recvd-init)
            self.ingress_mac = sha3_256(
                sxor(self.mac_secret, self.responder_nonce) + self.auth_recvd_init)

        ciphername = 'aes-256-ctr'
        iv = pyelliptic.Cipher.gen_IV(ciphername)
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
