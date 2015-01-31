# -*- coding: utf-8 -*-
"""
https://github.com/ethereum/go-ethereum/wiki/RLPx-----Node-Discovery-Protocol

"""
import time
import gevent
import gevent.socket
from devp2p import crypto
import rlp
from devp2p import utils
from devp2p import kademlia
from service import BaseService
import slogging
from gevent.server import DatagramServer
log = slogging.get_logger('discovery')


class DefectiveMessage(Exception):
    pass


class InvalidSignature(DefectiveMessage):
    pass


class PacketExpired(DefectiveMessage):
    pass


class Address(object):

    """
    Extend later, but make sure we deal with objects
    Multiaddress
    https://github.com/haypo/python-ipy
    """

    def __init__(self, protocol, ip, port):
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.version = 6 if ':' in ip else 4

    def ip_port(self):
        return self.ip, self.port

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return 'Address(%s/%s/%s)' % (self.protocol, self.ip, self.port)

    def to_dict(self):
        return dict(ip=self.ip, protocol=self.protocol, port=self.port)


class Node(kademlia.Node):

    def __init__(self, pubkey, address):
        assert len(pubkey) == 64 and isinstance(pubkey, str)
        assert address is None or isinstance(address, Address)
        self.pubkey = pubkey
        self.address = address
        self.id = rlp.big_endian_to_int(pubkey)
        self.reputation = 0
        self._expect_pong_until = 0

    def __repr__(self):
        return '<Node(%s)>' % self.pubkey[:4].encode('hex')

    def set_expect_pong(self, ts=None):
        self._expect_pong_until = ts or time.time() + .750  # 750 ms

    def is_expecting_pong(self):
        return time.time() < self._expect_pong_until


class DiscoveryProtocolTransport(object):

    def send(self, address, message):
        assert isinstance(address, Address)

    def receive(self, address, message):
        assert isinstance(address, Address)


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

    expiration = 5  # let messages expire after N secondes

    cmd_id_map = dict(ping=1, pong=2, find_node=3, neighbours=4)
    rev_cmd_id_map = dict((v, k) for k, v in cmd_id_map.items())

    def __init__(self, app, transport):
        self.app = app
        self.transport = transport
        self.privkey = app.config.get('p2p', 'privkey_hex').decode('hex')
        self.pubkey = crypto.privtopub(self.privkey)
        self.nodes = dict()   # nodeid->Node,  fixme should be loaded
        self.routing = kademlia.RoutingTable(kademlia.Node(self.pubkey))

    def get_node(self, nodeid, address=None):
        "return node or create new, update address if supplied"
        assert len(nodeid) == 512 / 8
        if nodeid not in self.nodes:
            self.nodes[nodeid] = Node(nodeid, address)
        node = self.nodes[nodeid]
        if address:
            assert isinstance(address, Address)
            node.address = address
        return node

    def sign(self, mdc):
        return crypto.sign(mdc, self.privkey)

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
        assert isinstance(payload, list)

        cmd_id = chr(cmd_id)
        expiration = utils.ienc4((time.time() + self.expiration))
        encoded_data = rlp.encode(payload + [expiration])
        mdc = self.mdc(cmd_id, encoded_data)
        assert len(mdc) == 32
        signature = self.sign(mdc)
        assert len(signature) == 65
        return signature + mdc + cmd_id + encoded_data

    def unpack(self, message):
        signature = message[:65]
        mdc = message[65:97]
        remote_pubkey = crypto.ecdsa_recover(mdc, signature)
        assert len(remote_pubkey) == 512 / 8
        if not crypto.verify(remote_pubkey, signature, mdc):
            raise InvalidSignature()
        cmd_id = ord(message[97])
        assert cmd_id in self.cmd_id_map.values()
        payload = rlp.decode(message[98:])
        assert isinstance(payload, list)
        expiration = utils.idec(payload.pop())
        if time.time() > expiration:
            raise PacketExpired()
        return remote_pubkey, cmd_id, payload, mdc

    def receive(self, address, message):
        assert isinstance(address, Address)
        remote_pubkey, cmd_id, payload, mdc = self.unpack(message)
        cmd = getattr(self, 'recv_' + self.rev_cmd_id_map[cmd_id])
        nodeid = remote_pubkey
        cmd(nodeid, payload, mdc)

    def send_ping(self, node):
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
        log.debug('sending ping', remoteid=node)
        payload = [self.app.config.get('p2p', 'listen_host'),
                   utils.ienc(self.app.config.getint('p2p', 'listen_port'))]
        message = self.pack(self.cmd_id_map['ping'], payload)

        node.set_expect_pong()
        assert node.is_expecting_pong()
        log.debug('set node to expect pong', remodeid=node)
        self.transport.send(node.address, message)

    def recv_ping(self, nodeid, payload, mcd):
        # update ip, port in node table
        ip, port = payload
        port = utils.idec(port)

        node = self.get_node(nodeid, Address('udp', ip, port))
        log.debug('received ping', remoteid=node)

        # reply with a pong
        self.send_pong(node, mcd)

    def send_pong(self, node, token):
        """
        ### Pong (type 0x02)

        Pong is the reply to a Ping packet.

        RLP encoding: **[** `Reply Token`, `Expiration` **]**

        Element       ||
        --------------|-----------------------------------------------
        `Reply Token` | content of the MDC element of the Ping packet
        """
        log.debug('sending pong', remoteid=node)
        message = self.pack(self.cmd_id_map['pong'], [token])
        self.transport.send(node.address, message)

    def recv_pong(self, nodeid,  payload, mcd):
        # check if we are expecting a pong
        if nodeid in self.nodes:
            node = self.get_node(nodeid)
            if node.is_expecting_pong():
                log.debug('received expected pong', remoteid=node)
                # update data
                return
            else:
                log.debug('received unexpected pong', remoteid=node)
        else:
            log.debug('received unexpected pong from unkown node')

    def send_find_node(self, node):
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

    def recv_find_node(self, nodeid, payload, mcd):
        pass

    def send_neighbours(self, node):
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

    def recv_neighbours(self, nodeid, payload, mcd):
        pass


class NodeDiscovery(BaseService, DiscoveryProtocolTransport):

    """
    Persist the list of known nodes with their reputation
    """

    name = 'discovery'

    def __init__(self, app):
        BaseService.__init__(self, app)
        log.info('NodeDiscovery init')
        self.protocol = DiscoveryProtocol(app=self.app, transport=self)

    @property
    def address(self):
        return Address('udp',
                       self.app.config.get('p2p', 'listen_host'),
                       self.app.config.getint('p2p', 'listen_port'))

    def send(self, address, message):
        assert isinstance(address, Address)
        sock = gevent.socket.socket(type=gevent.socket.SOCK_DGRAM)
        # sock.bind(('0.0.0.0', self.address.port))  # send from our recv port
        sock.connect(address.ip_port())
        log.debug('sending', size=len(message), to=address)
        sock.send(message)

    def receive(self, address, message):
        assert isinstance(address, Address)
        self.protocol.receive(address, message)

    def _handle_packet(self, message, ip_port):
        log.debug('handling packet', adress=ip_port, size=len(message))
        assert len(ip_port) == 2
        address = Address(protocol='udp', ip=ip_port[0], port=ip_port[1])
        self.receive(address, message)

    def start(self):
        log.info('starting discovery')
        # start a listening server
        host = self.app.config.get('p2p', 'listen_host')
        port = self.app.config.getint('p2p', 'listen_port')
        log.info('starting listener', port=port)
        self.server = DatagramServer((host, port), handle=self._handle_packet)
        self.server.start()
        super(NodeDiscovery, self).start()

    def _run(self):
        log.debug('_run called')
        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping discovery')
        self.server.stop()


if __name__ == '__main__':
    pass
