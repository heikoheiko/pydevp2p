#!/usr/bin/python

CURVE = 'secp256k1'
CIPHERNAME = 'aes-256-ctr'

# FIX PATH ON OS X ()
# https://github.com/yann2192/pyelliptic/issues/11
import os
import sys
_openssl_lib_paths = ['/usr/local/Cellar/openssl/']
for p in _openssl_lib_paths:
    if os.path.exists(p):
        p = os.path.join(p, os.listdir(p)[-1], 'lib')
        os.environ['DYLD_LIBRARY_PATH'] = p
        import pyelliptic
        if CIPHERNAME in pyelliptic.Cipher.get_all_cipher():
            break
if CIPHERNAME not in pyelliptic.Cipher.get_all_cipher():
    print 'required cipher %s not available in openssl library' % CIPHERNAME
    if sys.platform == 'darwin':
        print 'use homebrew to install newer openssl'
        print '> brew install openssl'
    sys.exit(1)

import bitcoin
from sha3 import sha3_256


class ECCx(pyelliptic.ECC):

    """
    Modified to work with raw_pubkey format used in RLPx
    and binding default curve and cipher
    """

    def __init__(self, raw_pubkey, raw_privkey=None):
        assert len(raw_pubkey) == 64  # 512bit
        pubkey_x = raw_pubkey[:32]
        pubkey_y = raw_pubkey[32:]
        pyelliptic.ECC.__init__(self, pubkey_x=pubkey_x, pubkey_y=pubkey_y,
                                raw_privkey=raw_privkey, curve=CURVE)

    @property
    def raw_pubkey(self):
        return self.pubkey_x + self.pubkey_y

    @property
    def raw_privkey(self):
        return self.privkey

    @classmethod
    def from_privkey(cls, raw_privkey):
        return cls(raw_pubkey=privtopub(raw_privkey), raw_privkey=raw_privkey)

    @staticmethod
    def encrypt(data, raw_pubkey):
        assert len(raw_pubkey) == 64
        px, py = raw_pubkey[:32], raw_pubkey[32:]
        return ECCx.raw_encrypt(data, px, py, curve=CURVE, ciphername=CIPHERNAME)

    def decrypt(self, data):
        return pyelliptic.ECC.decrypt(self, data, ciphername=CIPHERNAME)

    def sign(self, data):
        """
        pyelliptic.ECC.sign is DER-encoded
        https://bitcoin.stackexchange.com/questions/12554
        """
        signature = ecdsa_sign(data, self.raw_privkey)
        assert len(signature) == 65
        return signature

    def verify(self, signature, message):
        assert len(signature) == 65
        return ecdsa_verify(self.raw_pubkey, signature, message)


def lzpad32(x):
    return '\x00' * (32 - len(x)) + x


def _encode_sig(v, r, s):
    # vb in the middle
    # https://github.com/ethereum/go-ethereum/blob/develop/crypto/secp256k1/secp256.go#L154
    vb, rb, sb = chr(v), bitcoin.encode(r, 256), bitcoin.encode(s, 256)
    return lzpad32(rb) + vb + lzpad32(sb)


def _decode_sig(sig):
    return ord(sig[32]), bitcoin.decode(sig[0:32], 256), bitcoin.decode(sig[33:], 256)


def ecdsa_verify(pubkey, signature, message):
    assert len(signature) == 65
    assert len(pubkey) == 64
    return bitcoin.ecdsa_raw_verify(bitcoin.electrum_sig_hash(message),
                                    _decode_sig(signature), pubkey)
verify = ecdsa_verify


def ecdsa_sign(message, privkey):
    return _encode_sig(*bitcoin.ecdsa_raw_sign(bitcoin.electrum_sig_hash(message), privkey))
sign = ecdsa_sign


def ecdsa_recover(message, signature):
    assert len(signature) == 65
    pub = bitcoin.ecdsa_raw_recover(
        bitcoin.electrum_sig_hash(message), _decode_sig(signature))
    assert pub, 'pubkey could not be recovered'
    pub = bitcoin.encode_pubkey(pub, 'bin_electrum')
    assert len(pub) == 64
    return pub
recover = ecdsa_recover


def sha3(seed):
    return sha3_256(seed).digest()


def mk_privkey(seed):
    return sha3(seed)


def privtopub(raw_privkey):
    raw_pubkey = bitcoin.encode_pubkey(bitcoin.privtopub(raw_privkey), 'bin_electrum')
    assert len(raw_pubkey) == 64
    return raw_pubkey


def encrypt(data, raw_pubkey):
    """
    Encrypt data with ECIES method using the public key of the recipient.
    """
    assert len(raw_pubkey) == 64
    return ECCx.encrypt(data, raw_pubkey)
