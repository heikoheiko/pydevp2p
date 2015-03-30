
from devp2p.crypto import mk_privkey, privtopub
from devp2p.muxsession import MultiplexedSession
from devp2p.multiplexer import Packet
from devp2p.rlpxcipher import RLPxSession
from devp2p.protocol import P2PProtocol


class PeerMock(object):
    config = dict(p2p=dict(listen_port=3000, nodeid='\x00' * 64), client_version='pydevp2p')
    capabilities = [('p2p', 2), ('eth', 57)]
    send_packet = stop = receive_hello = lambda x: None


def test_session():

    proto = P2PProtocol(peer=PeerMock())
    hello_packet = proto.create_hello()

    responder_privkey = mk_privkey('secret1')
    responder = MultiplexedSession(responder_privkey, hello_packet=hello_packet,
                                   token_by_pubkey=dict())
    p0 = 0
    responder.add_protocol(p0)

    initiator_privkey = mk_privkey('secret2')
    initiator = MultiplexedSession(initiator_privkey, hello_packet=hello_packet,
                                   remote_pubkey=privtopub(responder_privkey))
    initiator.add_protocol(p0)

    # send auth
    msg = initiator.get_message()
    assert msg  # auth_init
    assert len(msg) == RLPxSession.auth_message_ct_length
    assert not initiator.get_packet()
    assert not responder.is_initiator

    # receive auth
    responder.add_message(msg)
    assert not responder.get_packet()
    assert responder.is_ready

    # send auth ack and hello
    ack_msg = responder.get_message()
    assert len(msg) >= RLPxSession.auth_ack_message_ct_length  # + hello
    hello_msg = responder.get_message()
    assert hello_msg

    # receive auth ack & hello
    initiator.add_message(ack_msg + hello_msg)
    assert initiator.is_ready
    hello_packet = initiator.get_packet()
    assert isinstance(hello_packet, Packet)

    # initiator sends hello
    hello_msg = initiator.get_message()
    assert hello_msg

    # hello received by responder
    responder.add_message(hello_msg)
    hello_packet = responder.get_packet()
    assert isinstance(hello_packet, Packet)

    # assert we received an actual hello packet
    data = proto.hello.decode_payload(hello_packet.payload)
    assert data['version']

    # test normal operation
    ping = proto.create_ping()
    initiator.add_packet(ping)
    msg = initiator.get_message()

    # receive ping
    responder.add_message(msg)
    ping_packet = responder.get_packet()
    assert isinstance(ping_packet, Packet)
    data = proto.ping.decode_payload(ping_packet.payload)

    # reply with pong
    pong = proto.create_ping()
    responder.add_packet(pong)
    msg = responder.get_message()

    # receive pong
    initiator.add_message(msg)
    pong_packet = initiator.get_packet()
    assert isinstance(pong_packet, Packet)
    data = proto.pong.decode_payload(pong_packet.payload)
