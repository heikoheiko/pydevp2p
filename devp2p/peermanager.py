import gevent
import socket
from gevent.server import StreamServer
from gevent.socket import create_connection
from service import BaseService
from protocol import P2PProtocol
from peer import Peer

import slogging
log = slogging.get_logger('peermgr')


class PeerManager(BaseService):

    """
    todo:
        on peer Hello adds services to peer
        connects new peers if there are too few
        selects peers based on a DHT
        keeps track of peer reputation
        saves/loads peers (rather discovery buckets) to disc


    connection strategy
        while num peers > min_num_peers:
                gen random id
                resolve closest node address
                connect closest node



    """
    name = 'peermanager'

    def __init__(self, app):
        BaseService.__init__(self, app)
        log.info('PeerManager init')
        self.peers = []

    def __repr__(self):
        return '<PeerManager>'

    def on_hello_received(self, p2pprotocol, data):
        log.debug('hello_reveived', peer=p2pprotocol.peer)
        # register more protocols

    def _start_peer(self, connection, address, is_inititator=False):
        log.debug('new connect', connection=connection)
        # create peer
        peer = Peer(self, connection)
        log.debug('created new peer', peer=peer)

        # register p2p protocol
        p2pprotocol = P2PProtocol(peer, cmd_offset=0, is_inititator=is_inititator)
        peer.register_protocol(p2pprotocol)
        self.peers.append(peer)

        # loop
        peer.start()
        log.debug('peer started', peer=peer)

    def connect(self, address):
        log.debug('connecting', address=address)
        """
        gevent.socket.create_connection(address, timeout=Timeout, source_address=None)
        Connect to address (a 2-tuple (host, port)) and return the socket object.
        Passing the optional timeout parameter will set the timeout
        getdefaulttimeout() is default
        """
        connection = create_connection(address)
        self._start_peer(connection, address, is_inititator=True)

    def _bootstrap(self):
        host = self.app.config['p2p']['bootstrap_host']
        port = self.app.config['p2p']['bootstrap_port']
        if host:
            log.info('connecting bootstrap server')
            try:
                self.connect((host, port))
            except socket.error:
                log.warn('connecting bootstrap server failed')

    def start(self):
        log.info('starting peermanager')
        # start a listening server
        ip = self.app.config['p2p']['listen_host']
        port = self.app.config['p2p']['listen_port']
        log.info('starting listener', host=ip, port=port)
        self.server = StreamServer((ip, port), handle=self._start_peer)
        self.server.start()
        self._bootstrap()
        super(PeerManager, self).start()

    def _run(self):
        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping peermanager')
        self.server.stop()
        for peer in self.peers:
            peer.stop()
