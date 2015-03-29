from devp2p import peermanager
from devp2p import peer
from devp2p import crypto
from devp2p.app import BaseApp
import gevent
import copy


def test_handshake():
    a_config = dict(client_version=1,
                    p2p=dict(listen_host='127.0.0.1', listen_port=3000,
                             privkey_hex=crypto.sha3('a').encode('hex')))
    b_config = copy.deepcopy(a_config)
    b_config['p2p']['listen_port'] = 3001
    b_config['p2p']['privkey_hex'] = crypto.sha3('b').encode('hex')

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
    pubkey = crypto.privtopub(b_config['p2p']['privkey'])
    a_peermgr.connect((host, port), remote_pubkey=pubkey)

    gevent.sleep(1)
    a_app.stop()
    b_app.stop()


if __name__ == '__main__':
    test_handshake()
