# -*- coding: utf-8 -*-
from devp2p import crypto


def get_ecc(secret=''):
    return crypto.ECCx.from_privkey(crypto.mk_privkey(secret))


def test_asymetric():
    bob = get_ecc('secret2')

    # enc / dec
    plaintext = "Hello Bob"
    ciphertext = crypto.encrypt(plaintext, bob.raw_pubkey)
    assert bob.decrypt(ciphertext) == plaintext


def test_signature():
    bob = get_ecc('secret2')

    # sign
    message = "Hello Alice"
    signature = bob.sign(message)

    # verify signature
    assert crypto.verify(bob.raw_pubkey, signature, message) is True
    assert crypto.ECCx(raw_pubkey=bob.raw_pubkey).verify(signature, message) is True

    # wrong signature
    message = "Hello Alicf"
    assert crypto.ECCx(raw_pubkey=bob.raw_pubkey).verify(signature, message) is False
    assert crypto.verify(bob.raw_pubkey, signature, message) is False


def test_recover():
    alice = get_ecc('secret1')
    message = 'hello bob'
    signature = alice.sign(message)
    assert len(signature) == 65
    assert crypto.verify(alice.raw_pubkey, signature, message) is True
    print len(signature)
    recovered_pubkey = crypto.ecdsa_recover(message, signature)
    assert len(recovered_pubkey) == 64
    assert alice.raw_pubkey == recovered_pubkey
