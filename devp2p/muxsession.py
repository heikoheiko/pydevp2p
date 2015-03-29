import gevent
import multiplexer
from rlpxcipher import RLPxSession
from crypto import ECCx


class MultiplexedSession(multiplexer.Multiplexer):

    max_window_size = 2**32  # FIXME, hack to disable framing till POC9

    def __init__(self, privkey, hello_packet, token_by_pubkey=dict(), remote_pubkey=None):
        self.is_initiator = bool(remote_pubkey)
        self.hello_packet = hello_packet
        self.message_queue = gevent.queue.Queue()  # wire msg egress queue
        self.packet_queue = gevent.queue.Queue()  # packet ingress queue
        ecc = ECCx(raw_privkey=privkey)
        self.rlpx_session = RLPxSession(
            ecc, is_initiator=bool(remote_pubkey), token_by_pubkey=token_by_pubkey)
        self.remote_pubkey = remote_pubkey
        self.token_by_pubkey = token_by_pubkey
        multiplexer.Multiplexer.__init__(self, frame_cipher=self.rlpx_session)
        if self.is_initiator:
            self._send_init_msg()

    @property
    def is_ready(self):
        # only authenticated and ready after successfully authenticated hello packet
        return self.rlpx_session.is_ready

    def _send_init_msg(self):
        auth_msg = self.rlpx_session.create_auth_message(self.remote_pubkey)
        auth_msg_ct = self.rlpx_session.encrypt_auth_message(auth_msg)
        self.message_queue.put(auth_msg_ct)

    def _add_message_during_handshake(self, msg):
        assert not self.is_ready
        session = self.rlpx_session
        if self.is_initiator:
            # expecting auth ack message
            session.decode_auth_ack_message(msg[:session.auth_ack_message_ct_length])
            session.setup_cipher()
            if len(msg) > session.auth_ack_message_ct_length:  # add remains (hello) to queue
                self._add_message_post_handshake(msg[session.auth_ack_message_ct_length:])
        else:
            # expecting auth_init
            session.decode_authentication(msg[:session.auth_message_ct_length])
            auth_ack_msg = session.create_auth_ack_message()
            auth_ack_msg_ct = session.encrypt_auth_ack_message(auth_ack_msg)
            self.message_queue.put(auth_ack_msg_ct)
            session.setup_cipher()
            if len(msg) > session.auth_message_ct_length:  # add remains (hello) to queue
                self._add_message_post_handshake(msg[session.auth_message_ct_length:])
        self.add_message = self._add_message_post_handshake

        # send hello
        assert session.is_ready
        self.add_packet(self.hello_packet)

    add_message = _add_message_during_handshake  # on_ready set to _add_message_post_handshake

    def _add_message_post_handshake(self, msg):
        "decodes msg and adds decoded packets to queue"
        for packet in self.decode(msg):
            self.packet_queue.put(packet)

    def get_message(self):
        "gets a message from the message queue"
        if not self.message_queue.empty():
            return self.message_queue.get_nowait()

    def add_packet(self, packet):
        "encodes a packet and adds the message(s) to the msg queue"
        assert isinstance(packet, multiplexer.Packet)
        assert self.is_ready  # don't send anything until handshake is finished
        multiplexer.Multiplexer.add_packet(self, packet)
        for f in self.pop_all_frames():
            self.message_queue.put(f.as_bytes())

    def get_packet(self):
        "gets a packet from the packet queue"
        if not self.packet_queue.empty():
            return self.packet_queue.get_nowait()
