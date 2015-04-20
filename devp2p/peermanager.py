import random
import gevent
import socket
import atexit
from gevent.server import StreamServer
from gevent.socket import create_connection, timeout
from service import WiredService
from protocol import BaseProtocol
from p2p_protocol import P2PProtocol
from discovery import NodeDiscovery
import kademlia
from peer import Peer
import crypto
import utils

import slogging
log = slogging.get_logger('peermgr')


class PeerManager(WiredService):

    """
    todo:
        connects new peers if there are too few
        selects peers based on a DHT
        keeps track of peer reputation
        saves/loads peers (rather discovery buckets) to disc

    connection strategy
        for service which requires peers
            while num peers > min_num_peers:
                    gen random id
                    resolve closest node address
                    [ideally know their services]
                    connect closest node
    """
    name = 'peermanager'
    required_services = []
    wire_protocol = P2PProtocol
    default_config = dict(p2p=dict(bootstrap_nodes=[],
                                   min_peers=5,
                                   max_peers=10,
                                   listen_port=30303,
                                   listen_host='0.0.0.0'),
                          node=dict(privkey_hex=''))

    connect_timeout = 2.

    def __init__(self, app):
        log.info('PeerManager init')
        self.peers = []
        self.errors = PeerErrors()
        WiredService.__init__(self, app)

        # setup nodeid based on privkey
        if 'id' not in self.config['p2p']:
            self.config['node']['id'] = crypto.privtopub(
                self.config['node']['privkey_hex'].decode('hex'))

    def on_hello_received(self, p2p_proto, data):
        log.debug('hello_received', peer=p2p_proto.peer)
        # register more protocols

    @property
    def wired_services(self):
        return [s for s in self.app.services.values() if isinstance(s, WiredService)]

    def broadcast(self, protocol, command_name, args=[], kargs={},
                  num_peers=None, exclude_protos=[]):
        log.debug('broadcasting', protcol=protocol, command=command_name,
                  num_peers=num_peers, exclude_protos=exclude_protos)
        assert num_peers is None or num_peers > 0
        peers_with_proto = [p for p in self.peers
                            if protocol in p.protocols and p not in exclude_protos]

        if not peers_with_proto:
            log.debug('no peers with proto found', protos=[p.protocols for p in self.peers])
        num_peers = num_peers or len(peers_with_proto)
        for p in random.sample(peers_with_proto, min(num_peers, len(peers_with_proto))):
            log.debug('broadcasting to', proto=p.protocols[protocol])
            func = getattr(p.protocols[protocol], 'send_' + command_name)
            func(*args, **kargs)

    def _start_peer(self, connection, address, remote_pubkey=None):
        log.debug('new connect', connection=connection)
        # create peer
        peer = Peer(self, connection, remote_pubkey=remote_pubkey)
        log.debug('created new peer', peer=peer)
        self.peers.append(peer)

        # loop
        peer.start()
        log.debug('peer started', peer=peer)

    def connect(self, address, remote_pubkey):
        log.debug('connecting', address=address)
        """
        gevent.socket.create_connection(address, timeout=Timeout, source_address=None)
        Connect to address (a 2-tuple (host, port)) and return the socket object.
        Passing the optional timeout parameter will set the timeout
        getdefaulttimeout() is default
        """
        try:
            connection = create_connection(address, timeout=self.connect_timeout)
        except socket.timeout:
            log.info('connection timeout', address=address, timeout=self.connect_timeout)
            self.errors.add(address, 'connection timeout')
            return False
        except socket.error as e:
            log.info('connection error', errno=e.errno, reason=e.strerror)
            self.errors.add(address, 'connection error')
            return False
        self._start_peer(connection, address, remote_pubkey)
        return True

    def _bootstrap(self, bootstrap_nodes=[]):
        for uri in bootstrap_nodes:
            ip, port, pubkey = utils.host_port_pubkey_from_uri(uri)
            log.info('connecting bootstrap server', uri=uri)
            try:
                self.connect((ip, port), pubkey)
            except socket.error:
                log.warn('connecting bootstrap server failed')

    def start(self):
        log.info('starting peermanager')
        # start a listening server
        ip = self.config['p2p']['listen_host']
        port = self.config['p2p']['listen_port']
        log.info('starting listener', host=ip, port=port)
        self.server = StreamServer((ip, port), handle=self._start_peer)
        self.server.start()
        self._bootstrap()
        super(PeerManager, self).start()

    def num_peers(self):
        return len([p for p in self.peers if p])

    def _run(self):
        log.info('waiting for bootstrap')
        gevent.sleep(3)
        loop_delay = 1
        while not self.is_stopped:
            #log.info('in loop', num_peers=len(self.peers))
            num_peers, min_peers = self.num_peers(), self.config['p2p']['min_peers']
            kademlia_proto = self.app.services.discovery.protocol.kademlia
            if num_peers < min_peers:
                log.info('missing peers', num_peers=num_peers,
                         min_peers=min_peers, known=len(kademlia_proto.routing))
                nodeid = kademlia.random_nodeid()
                kademlia_proto.find_node(nodeid)  # fixme, should be a task
                gevent.sleep(2)  # wait for results
                neighbours = kademlia_proto.routing.neighbours(nodeid, 1)
                node = neighbours[0]
                log.info('connecting random', node=node)
                local_pubkey = crypto.privtopub(self.config['node']['privkey_hex'].decode('hex'))
                if node.pubkey == local_pubkey:
                    continue
                if node.pubkey in [p.remote_pubkey for p in self.peers]:
                    continue
                self.connect((node.address.ip, node.address.port), node.pubkey)
            gevent.sleep(loop_delay)

        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping peermanager')
        self.server.stop()
        for peer in self.peers:
            peer.stop()
        super(PeerManager, self).stop()


class PeerErrors(object):

    def __init__(self):
        self.errors = dict()  # node: ['error',]
        self.client_versions = dict()  # address: client_version

        def report():
            for k, v in self.errors.items():
                print k, self.client_versions.get(k, '')
                for e in v:
                    print '\t', e

        atexit.register(report)

    def add(self, address, error, client_version=''):
        self.errors.setdefault(address, []).append(error)
        if client_version:
            self.client_versions[address] = client_version
