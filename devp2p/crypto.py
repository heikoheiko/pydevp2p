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
if not CIPHERNAME in pyelliptic.Cipher.get_all_cipher():
    print 'required cipher %s not available in openssl library' % CIPHERNAME
    if sys.platform == 'darwin':
        print 'use homebrew to install newer openssl'
        print '> brew install openssl'
    sys.exit(1)

import bitcoin
from sha3 import sha3_256


class ECCx(pyelliptic.ECC):

    def __init__(self, pubkey=None, privkey=None):
        assert len(pubkey) == 64  # 512bit
        if pubkey:
            pubkey_x = pubkey[:32]
            pubkey_y = pubkey[32:]
        else:
            pubkey_x, pubkey_y = None, None
        pyelliptic.ECC.__init__(self, pubkey_x=pubkey_x, pubkey_y=pubkey_y,
                                raw_privkey=privkey, curve=CURVE)

    def get_pubkey(self):
        return self.pubkey_x + self.pubkey_y
    pubkey = property(get_pubkey)

    def get_privkey(self):
        return self.privkey

def ecdsa_recover(msg, sig):
    return bitcoin.encode_pubkey(bitcoin.ecdsa_raw_recover(
                                 bitcoin.electrum_sig_hash(msg),
                                 bitcoin.decode_sig(sig)),
                                 'bin_electrum')

def sha3(seed):
    return sha3_256(seed).digest()


def mk_privkey(seed):
    return sha3(seed)


def privtopub(privkey):
    r = bitcoin.encode_pubkey(bitcoin.privtopub(privkey), 'bin_electrum')
    assert len(r) == 64
    return r

def encrypt(data, pubkey):
    return pyelliptic.encrypt(data, pubkey, ephemcurve=CURVE, ciphername=CIPHERNAME)
