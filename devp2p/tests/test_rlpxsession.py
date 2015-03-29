
from devp2p.rlpxcipher import RLPxSession, FormatError
from devp2p.crypto import mk_privkey, ECCx, sha3
from devp2p.multiplexer import Multiplexer, Packet
import struct


def test_session():
    initiator = RLPxSession(ECCx(raw_privkey=mk_privkey('secret1')), is_initiator=True)
    initiator_pubk = initiator.ecc.raw_pubkey
    responder = RLPxSession(ECCx(raw_privkey=mk_privkey('secret2')))
    responder_pubk = responder.ecc.raw_pubkey

    auth_msg = initiator.create_auth_message(remote_pubkey=responder_pubk)
    auth_msg_ct = initiator.encrypt_auth_message(auth_msg, responder_pubk)

    responder.decode_authentication(auth_msg_ct)
    auth_ack_msg = responder.create_auth_ack_message()
    auth_ack_msg_ct = responder.encrypt_auth_ack_message(auth_ack_msg, initiator_pubk)

    initiator.decode_auth_ack_message(auth_ack_msg_ct)

    initiator.setup_cipher()
    responder.setup_cipher()

    assert responder.ecdhe_shared_secret == initiator.ecdhe_shared_secret
    assert responder.token == initiator.token
    assert responder.aes_secret == initiator.aes_secret
    assert responder.mac_secret == initiator.mac_secret

    assert responder.egress_mac.digest() == initiator.ingress_mac.digest()
    assert responder.egress_mac.digest() == initiator.ingress_mac.digest()
    assert responder.ingress_mac.digest() == initiator.egress_mac.digest()
    assert responder.ingress_mac.digest() == initiator.egress_mac.digest()
    assert responder.mac_secret == initiator.mac_secret

    return initiator, responder


def test_multiplexing():
    initiator, responder = test_session()
    imux = Multiplexer(frame_cipher=initiator)
    rmux = Multiplexer(frame_cipher=responder)
    p1 = 1
    imux.add_protocol(p1)
    rmux.add_protocol(p1)

    packet1 = Packet(p1, cmd_id=0, payload='\x00' * 100)
    imux.add_packet(packet1)
    msg = imux.pop_all_frames_as_bytes()
    packets = rmux.decode(msg)
    assert len(packets) == 1
    assert packet1 == packets[0]


def test_many_sessions():
    for i in range(20):
        test_session()


def test_macs():
    initiator, responder = test_session()
    assert responder.egress_mac.digest() == initiator.ingress_mac.digest()
    assert responder.ingress_mac.digest() == initiator.egress_mac.digest()
    assert initiator.egress_mac.digest() == responder.ingress_mac.digest()
    for i in range(5):
        msg = 'test'
        initiator.egress_mac.update(msg)
        responder.ingress_mac.update(msg)
        assert initiator.egress_mac.digest() == responder.ingress_mac.digest(), i


def test_mac_enc():
    initiator, responder = test_session()
    msg = 'a' * 16
    assert responder.mac_enc(msg) == initiator.mac_enc(msg)


def test_aes_enc():
    initiator, responder = test_session()
    msg = 'test'
    c = initiator.aes_enc.update(msg)
    assert len(c) == len(msg)
    d = responder.aes_dec.update(c)
    assert len(d) == len(msg)
    assert d == msg


def rzpad16(data):
    if len(data) % 16:
        data += '\x00' * (16 - len(data) % 16)
    return data


def test_encryption():
    initiator, responder = test_session()
    for i in range(5):
        msg_frame = sha3(str(i) + 'f') * i + 'notpadded'
        msg_frame_padded = rzpad16(msg_frame)
        frame_size = len(msg_frame)
        msg_header = struct.pack('>I', frame_size)[1:] + sha3(str(i))[:16 - 3]
        msg_ct = initiator.encrypt(msg_header, msg_frame_padded)
        r = responder.decrypt(msg_ct)
        assert r['header'] == msg_header
        assert r['frame'] == msg_frame

    for i in range(5):
        msg_frame = sha3(str(i) + 'f')
        msg_header = struct.pack('>I', len(msg_frame))[1:] + sha3(str(i))[:16 - 3]
        msg_ct = responder.encrypt(msg_header, msg_frame)
        r = initiator.decrypt(msg_ct)
        assert r['header'] == msg_header
        assert r['frame'] == msg_frame


def test_body_length():
    initiator, responder = test_session()
    msg_frame = sha3('test') + 'notpadded'
    msg_frame_padded = rzpad16(msg_frame)
    frame_size = len(msg_frame)
    msg_header = struct.pack('>I', frame_size)[1:] + sha3('x')[:16 - 3]
    msg_ct = initiator.encrypt(msg_header, msg_frame_padded)
    r = responder.decrypt(msg_ct)
    assert r['header'] == msg_header
    assert r['frame'] == msg_frame

    # test excess data
    msg_ct2 = initiator.encrypt(msg_header, msg_frame_padded)
    r = responder.decrypt(msg_ct2 + 'excess data')
    assert r['header'] == msg_header
    assert r['frame'] == msg_frame
    assert r['bytes_read'] == len(msg_ct)

    # test data underflow
    data = initiator.encrypt(msg_header, msg_frame_padded)
    header = responder.decrypt_header(data[:32])
    body_size = struct.unpack('>I', '\x00' + header[:3])[0]
    exception_raised = False
    try:
        responder.decrypt_body(data[32:-1], body_size)
    except FormatError:
        exception_raised = True
    assert exception_raised
