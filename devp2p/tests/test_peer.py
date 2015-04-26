from devp2p import peermanager
from devp2p import crypto
from devp2p.app import BaseApp
import devp2p.muxsession
import rlp
import devp2p.p2p_protocol
import time
import gevent
import copy


def get_connected_apps():
    a_config = dict(p2p=dict(listen_host='127.0.0.1', listen_port=3000),
                    node=dict(privkey_hex=crypto.sha3('a').encode('hex')))
    b_config = copy.deepcopy(a_config)
    b_config['p2p']['listen_port'] = 3001
    b_config['node']['privkey_hex'] = crypto.sha3('b').encode('hex')

    a_app = BaseApp(a_config)
    peermanager.PeerManager.register_with_app(a_app)
    a_app.start()

    b_app = BaseApp(b_config)
    peermanager.PeerManager.register_with_app(b_app)
    b_app.start()

    a_peermgr = a_app.services.peermanager
    b_peermgr = b_app.services.peermanager

    # connect
    host = b_config['p2p']['listen_host']
    port = b_config['p2p']['listen_port']
    pubkey = crypto.privtopub(b_config['node']['privkey_hex'].decode('hex'))
    a_peermgr.connect((host, port), remote_pubkey=pubkey)

    return a_app, b_app


def test_handshake():
    a_app, b_app = get_connected_apps()
    gevent.sleep(1)
    a_app.stop()
    b_app.stop()


def test_big_transfer():

    class transfer(devp2p.p2p_protocol.BaseProtocol.command):
        cmd_id = 4
        structure = [('raw_data', rlp.sedes.binary)]

        def create(self, proto, raw_data=''):
            return [raw_data]

    # money patches
    devp2p.p2p_protocol.P2PProtocol.transfer = transfer
    devp2p.muxsession.MultiplexedSession.max_window_size = 8 * 1024

    a_app, b_app = get_connected_apps()
    gevent.sleep(.1)

    a_protocol = a_app.services.peermanager.peers[0].protocols[devp2p.p2p_protocol.P2PProtocol]
    b_protocol = b_app.services.peermanager.peers[0].protocols[devp2p.p2p_protocol.P2PProtocol]

    st = time.time()

    def cb(proto, **data):
        print 'took', time.time() - st, len(data['raw_data'])

    b_protocol.receive_transfer_callbacks.append(cb)
    raw_data = '0' * 1 * 1000 * 100
    a_protocol.send_transfer(raw_data=raw_data)

    # 0.03 secs for 0.1mb
    # 0.28 secs for 1mb
    # 2.7 secs for 10mb
    # 3.7 MB/s == 30Mbit

    gevent.sleep(1)
    a_app.stop()
    b_app.stop()
    gevent.sleep(0.1)


def connect_go():
    a_config = dict(p2p=dict(listen_host='127.0.0.1', listen_port=3000),
                    node=dict(privkey_hex=crypto.sha3('a').encode('hex')))

    a_app = BaseApp(a_config)
    peermanager.PeerManager.register_with_app(a_app)
    a_app.start()

    a_peermgr = a_app.services.peermanager

    # connect
    pubkey = "6ed2fecb28ff17dec8647f08aa4368b57790000e0e9b33a7b91f32c41b6ca9ba21600e9a8c44248ce63a71544388c6745fa291f88f8b81e109ba3da11f7b41b9".decode(
        'hex')
    a_peermgr.connect(('127.0.0.1', 30303), remote_pubkey=pubkey)
    gevent.sleep(50)
    a_app.stop()


if __name__ == '__main__':
    # ethereum -loglevel 5 --bootnodes ''
    import ethereum.slogging
    ethereum.slogging.configure(config_string=':debug')
    # connect_go()
    test_big_transfer()
