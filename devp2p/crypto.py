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
        https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
        DER-encoded signature has the following form:

        0x30: a header byte indicating a compound structure.
        A 1-byte length descriptor for all what follows.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the R value
        The R coordinate, as a big-endian integer.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the S value.
        The S coordinate, as a big-endian integer.

        Where initial 0x00 bytes for R and S are not allowed, except when their first byte would
        otherwise be above 0x7F (in which case a single 0x00 in front is required).
        Also note that inside transaction signatures, an extra hashtype byte follows the
        actual signature data.
        """
        # der_signature = pyelliptic.ECC.sign(self, data)
        import base64
        signature_b64 = bitcoin.ecdsa_sign(data, self.raw_privkey)
        signature = base64.b64decode(signature_b64)
        assert len(signature) == 65
        return signature

    def verify(self, signature, message):
        assert len(signature) == 65
        return ecdsa_verify(self.raw_pubkey, signature, message)


def _encode_sig(v, r, s):
    vb, rb, sb = chr(v), bitcoin.encode(r, 256), bitcoin.encode(s, 256)
    return vb + '\x00' * (32 - len(rb)) + rb + '\x00' * (32 - len(sb)) + sb


def _decode_sig(sig):
    return ord(sig[0]), bitcoin.decode(sig[1:33], 256), bitcoin.decode(sig[33:], 256)


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


if __name__ == '__main__':
    pass
