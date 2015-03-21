#!/usr/bin/python
"""
https://github.com/ethereum/go-ethereum/blob/develop/crypto/ecies/ecies.go

https://github.com/ethereum/cpp-ethereum/blob/develop/libp2p/RLPxHandshake.cpp#L48
https://github.com/ethereum/cpp-ethereum/blob/develop/libdevcrypto/CryptoPP.cpp#L149

ECIES
http://www.cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme
https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
"""
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
from hashlib import sha256


class ECCx(pyelliptic.ECC):

    """
    Modified to work with raw_pubkey format used in RLPx
    and binding default curve and cipher
    """

    def __init__(self, raw_pubkey=None, raw_privkey=None):
        if raw_privkey:
            assert not raw_pubkey
            raw_pubkey = privtopub(raw_privkey)
        if raw_pubkey:
            _, pubkey_x, pubkey_y, _ = self._decode_pubkey(raw_pubkey)
        else:
            pubkey_x, pubkey_y = None, None
        pyelliptic.ECC.__init__(self, pubkey_x=pubkey_x, pubkey_y=pubkey_y,
                                raw_privkey=raw_privkey, curve=CURVE)

    @property
    def raw_pubkey(self):
        return self.pubkey_x + self.pubkey_y

    @staticmethod
    def _decode_pubkey(raw_pubkey):
        assert len(raw_pubkey) == 64
        pubkey_x = raw_pubkey[:32]
        pubkey_y = raw_pubkey[32:]
        return CURVE, pubkey_x, pubkey_y, 64

    def get_ecdh_key(self, raw_pubkey):
        "Compute public key with the local private key and returns a 256bits shared key"
        _, pubkey_x, pubkey_y, _ = self._decode_pubkey(raw_pubkey)
        key = self.raw_get_ecdh_key(pubkey_x, pubkey_y)
        assert len(key) == 32
        return key

    @property
    def raw_privkey(self):
        return self.privkey

    @staticmethod
    def encrypt(data, raw_pubkey):
        assert len(raw_pubkey) == 64
        px, py = raw_pubkey[:32], raw_pubkey[32:]
        return ECCx._raw_encrypt(data, px, py, curve=CURVE, ciphername=CIPHERNAME)

    @staticmethod
    def _raw_encrypt(data, pubkey_x, pubkey_y, curve=CURVE, ciphername=CIPHERNAME):
        ephem = ECCx()
        key = sha256(ephem.raw_get_ecdh_key(pubkey_x, pubkey_y)).digest()
        key_e, key_m = key[:16], key[16:]
        pubkey = ephem.raw_pubkey
        assert len(pubkey) == 64
        iv = pyelliptic.OpenSSL.rand(pyelliptic.OpenSSL.get_cipher(ciphername).get_blocksize())
        assert len(iv) == 16
        ctx = pyelliptic.Cipher(key_e, iv, 1, ciphername)
        ciphertext = ctx.ciphering(data)
        assert len(ciphertext) == len(data)
        msg = chr(0x04) + pubkey + iv + ciphertext
        mac = pyelliptic.hmac_sha256(key_m, msg)
        assert len(mac) == 32
        msg += mac
        assert len(msg) == 1 + 64 + 16 + 32 + len(data) == 113 + len(data)
        return msg

    def _decrypt(self, data):
        return pyelliptic.ECC.decrypt(self, data, ciphername=CIPHERNAME)

    def decrypt(self, data, ciphername=CIPHERNAME):
        """
        Decrypt data with ECIES method using the local private key

        CIPHERNAME = 'aes-128-ctr' ???
        """
        blocksize = pyelliptic.OpenSSL.get_cipher(ciphername).get_blocksize()
        assert data[0] == chr(0x04)
        pubkey = data[1:1 + 64]
        pubkey_x, pubkey_y = pubkey[:32], pubkey[32:],
        iv = data[1 + 64:1 + 64 + blocksize]
        ciphertext = data[1 + 64 + blocksize:- 32]
        mac = data[-32:]
        assert 1 + len(pubkey) + len(iv) + len(ciphertext) + len(mac) == len(data)
        key = sha256(self.raw_get_ecdh_key(pubkey_x, pubkey_y)).digest()
        key_e, key_m = key[:16], key[16:]
        if not pyelliptic.equals(pyelliptic.hmac_sha256(key_m, data[:- 32]), mac):
            raise RuntimeError("Fail to verify data")
        ctx = pyelliptic.Cipher(key_e, iv, 0, ciphername)
        return ctx.ciphering(ciphertext)

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
    assert isinstance(v, (int, long))
    assert v in (27, 28)
    vb, rb, sb = chr(v - 27), bitcoin.encode(r, 256), bitcoin.encode(s, 256)
    return lzpad32(rb) + lzpad32(sb) + vb


def _decode_sig(sig):
    return ord(sig[64]) + 27, bitcoin.decode(sig[0:32], 256), bitcoin.decode(sig[32:64], 256)


def ecdsa_verify(pubkey, signature, message):
    assert len(signature) == 65
    assert len(pubkey) == 64
    return bitcoin.ecdsa_raw_verify(message, _decode_sig(signature), pubkey)
verify = ecdsa_verify


def ecdsa_sign(message, privkey):
    s = _encode_sig(*bitcoin.ecdsa_raw_sign(message, privkey))
    return s

sign = ecdsa_sign


def ecdsa_recover(message, signature):
    assert len(signature) == 65
    pub = bitcoin.ecdsa_raw_recover(message, _decode_sig(signature))
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
