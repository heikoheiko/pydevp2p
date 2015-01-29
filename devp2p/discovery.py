# -*- coding: utf-8 -*-
"""
https://github.com/ethereum/go-ethereum/wiki/RLPx-----Node-Discovery-Protocol
https://github.com/gevent/gevent/blob/master/examples/udp_client.py
https://github.com/gevent/gevent/blob/master/examples/udp_server.py

Fragen:

    - where to access node priv/pubkey?
        - privkey in config() for now
        - app.keys_service

    app.keys_service
        .pubkey
        .sign
        .decrypt


    - how to test?

    - addresses

    - upnp


"""
import time
import gevent
import struct
import json
import crypto
import rlp
from gevent import Greenlet
from service import BaseService
import slogging
from gevent.server import DatagramServer
log = slogging.get_logger('discovery')


class InvalidSignature(Exception):
    pass


class Address(object):
    # https://github.com/haypo/python-ipy

    def __init__(self, protocol, ip, port):
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.version = 6 if ':' in ip else 4

"""
# Node Discovery Protocol

**Node**: an entity on the network
**Node ID**: 512 bit public key of node

The Node Discovery protocol provides a way to find RLPx nodes
that can be connected to. It uses a Kademlia-like protocol to maintain a
distributed database of the IDs and endpoints of all listening nodes.

Each node keeps a node table as described in the Kademlia paper
[[Maymounkov, Mazières 2002][kad-paper]]. The node table is configured
with a bucket size of 16 (denoted `k` in Kademlia), concurrency of 3
(denoted `α` in Kademlia), and 8 bits per hop (denoted `b` in
Kademlia) for routing. The eviction check interval is 75 milliseconds,
and the idle bucket-refresh interval is
3600 seconds.

In order to maintain a well-formed network, RLPx nodes should try to connect
to an unspecified number of close nodes. To increase resilience against Sybil attacks,
nodes should also connect to randomly chosen, non-close nodes.

Each node runs the UDP-based RPC protocol defined below. The
`FIND_DATA` and `STORE` requests from the Kademlia paper are not part
of the protocol since the Node Discovery Protocol does not provide DHT
functionality.

[kad-paper]: http://www.cs.rice.edu/Conferences/IPTPS02/109.pdf

## Joining the network

When joining the network, fills its node table by perfoming a
recursive Find Node operation with its own ID as the `Target`. The
initial Find Node request is sent to one or more bootstrap nodes.

## RPC Protocol

RLPx nodes that want to accept incoming connections should listen on
the same port number for UDP packets (Node Discovery Protocol) and
TCP connections (RLPx protocol).

All requests time out after are 300ms. Requests are not re-sent.

"""


class DiscoveryProtocol(object):

    """
    ## Packet Data
    All packets contain an `Expiration` date to guard against replay attacks.
    The date should be interpreted as a UNIX timestamp.
    The receiver should discard any packet whose `Expiration` value is in the past.
    """

    cmd_id_map = dict(ping=1, pong=2, find_node=3, neighbours=4)

    def __init__(self, app, transport):
        self.transport = transport
        self.pubkey = None

    def sign(self, mdc):
        return mdc

    def mdc(self, cmd_id, encoded_data, pubkey=None):
        """Ensures integrity of packet, `SHA3(sender-pubkey || type || data)`"""
        pubkey = pubkey or self.pubkey
        assert len(cmd_id) == 1
        return crypto.sha3(pubkey + cmd_id + encoded_data)

    def pack(self, cmd_id, payload):
        """
        UDP packets are structured as follows:

        Offset  |
        0       | signature | Ensures authenticity of sender, `SIGN(sender-privkey, MDC)`
        65      | MDC       | Ensures integrity of packet, `SHA3(sender-pubkey || type || data)`
        97      | type      | Single byte in range [1, 4] that determines the structure of Data
        98      | data      | RLP encoded, see section Packet Data

        The packets are signed and authenticated. The sender's Node ID is determined by
        recovering the public key from the signature.

            sender-pubkey = ECRECOVER(Signature)

        The integrity of the packet can then be verified by computing the
        expected MDC of the packet as:

            MDC = SHA3(sender-pubkey || type || data)

        As an optimization, implementations may look up the public key by
        the UDP sending address and compute MDC before recovering the sender ID.
        If the MDC values do not match, the packet can be dropped.
        """
        assert cmd_id in self.cmd_id_map.values()
        assert isinstance(payload, (str, list))

        cmd_id = chr(cmd_id)
        encoded_data = rlp.encode(payload)
        mdc = self.mdc(cmd_id, encoded_data)
        assert len(mdc) == 32
        signature = self.sign(mdc)
        assert len(signature) == 65
        return signature + mdc + cmd_id + encoded_data

    def unpack(self, message):
        signature = message[:65]
        mdc = message[65:97]
        remote_pubkey = crypto.ecdsa_recover(mdc, signature)
        assert len(remote_pubkey) == 512
        if not crypto.ecdsa_verify(mdc, signature, remote_pubkey):
            raise InvalidSignature()
        cmd_id = ord(message[97])
        assert cmd_id in self.cmd_id_map.values()
        data = rlp.decode(message[98:])
        return remote_pubkey, cmd_id, data

    def receive(self, address, message):
        remote_pubkey, cmd_id, data = self.unpack(message)
        cmd = getattr(self, 'recv_%s' + self.cmd_id_map[cmd_id])
        cmd(address, remote_pubkey, data)

    def send_ping(self):
        """
        ### Ping (type 0x01)

        Ping packets can be sent and received at any time. The receiver should
        reply with a Pong packet and update the IP/Port of the sender in its
        node table.

        RLP encoding: **[** `IP`, `Port`, `Expiration` **]**

        Element   ||
        ----------|------------------------------------------------------------
        `IP`      | (length 4 or 16) IP address on which the node is listening
        `Port`    | listening port of the node
        """

    def recv_ping(self, data):

    def pong(self):
        """
        ### Pong (type 0x02)

        Pong is the reply to a Ping packet.

        RLP encoding: **[** `Reply Token`, `Expiration` **]**

        Element       ||
        --------------|-----------------------------------------------
        `Reply Token` | content of the MDC element of the Ping packet
        """

    def find_node(self):
        """
        ### Find Node (type 0x03)

        Find Node packets are sent to locate nodes close to a given target ID.
        The receiver should reply with a Neighbors packet containing the `k`
        nodes closest to target that it knows about.

        RLP encoding: **[** `Target`, `Expiration` **]**

        Element  ||
        ---------|--------------------
        `Target` | is the target ID
        """

    def neighbours(self):
        """
        ### Neighbors (type 0x04)

        Neighbors is the reply to Find Node. It contains up to `k` nodes that
        the sender knows which are closest to the requested `Target`.

        RLP encoding: **[ [** `Node₁`, `Node₂`, ..., `Nodeₙ` **]**, `Expiration` **]**
        Each `Node` is a list of the form **[** `Version`, `IP`, `Port`, `ID` **]**

        Element   ||
        ----------|---------------------------------------------------------------
        `ID`      | The advertised node's public key
        `Version` | the RLPx protocol version that the node implements
        `IP`      | (length 4 or 16) IP address on which the node is listening
        `Port`    | listening port of the node
        """


class NodeDiscovery(BaseService):

    """
    """

    name = 'NodeDiscovery'

    def __init__(self, app):
        BaseService.__init__(self, app)
        log.info('NodeDiscovery init')
        pubkey = app.config.pubkey  # FIXME

    def create_packet(self, cmd_id, payload):
        pass

    def _handle_packet(self, data, address):
        log.debug('handling packet', adress=address[0])
        self.socket.sendto('Received %s bytes' % len(data), address)

    def start(self):
        log.info('starting discovery')
        # start a listening server
        port = self.app.config.getint('p2p', 'listen_port')
        log.info('starting listener', port=port)
        self.server = EchoServer((host, port), handle=self._handle_packet)
        self.server.start()
        super(NodeDiscovery, self).start()

    def _run(self):
        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping discovery')
        self.server.stop()


class EchoServer(DatagramServer):

    def handle(self, data, address):
        print('%s: got %r' % (address[0], data))
        self.socket.sendto('Received %s bytes' % len(data), address)

if __name__ == '__main__':
    print('Receiving datagrams on :9000')
    EchoServer(':9000').serve_forever()


if __name__ == '__main__':
    main()
