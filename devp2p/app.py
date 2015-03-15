from UserDict import IterableUserDict
from service import BaseService
from slogging import get_logger
import crypto
log = get_logger('app')


class BaseApp(object):

    def __init__(self, config):
        self.config = config
        self.services = IterableUserDict()

    def register_service(self, service):
        """
        registeres protocol with peer, which will be accessible as
        peer.<protocol.name> (e.g. peer.p2p or peer.eth)
        """
        assert isinstance(service, BaseService)
        assert service.name not in self.services
        log.info('registering service', service=service.name)
        self.services[service.name] = service
        setattr(self.services, service.name, service)

    def deregister_service(self, service):
        assert isinstance(service, BaseService)
        self.services.remove(service)
        delattr(self.services, service.name)

    def start(self):
        for service in self.services.values():
            service.start()

    def stop(self):
        for service in self.services.values():
            service.stop()


if __name__ == '__main__':
    # config
    import yaml
    import io
    import sys
    import signal
    import gevent
    from peermanager import PeerManager
    from jsonrpc import JSONRPCServer
    from discovery import NodeDiscovery
    import slogging
    log = slogging.get_logger('app')

    # read config
    sample_config = """
p2p:
    num_peers: 10
    bootstrap_host: localhost
    bootstrap_port: 30303
    listen_host: 127.0.0.1
    listen_port: 30302
    privkey_hex: 65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b
    """
    if len(sys.argv) == 1:
        config = yaml.load(io.BytesIO(sample_config))
        pubkey = crypto.privtopub(config['p2p']['privkey_hex'].decode('hex'))
        config['p2p']['node_id'] = crypto.sha3(pubkey)
    else:
        fn = sys.argv[1]
        log.info('loading config from', fn=fn)
        config = yaml.load(open(fn))

    print config
    # create app
    app = BaseApp(config)

    # register services
    PeerManager.register_with_app(app)
    JSONRPCServer.register_with_app(app)
    NodeDiscovery.register_with_app(app)

    # start app
    app.start()

    # wait for interupt
    evt = gevent.event.Event()
    # gevent.signal(signal.SIGQUIT, gevent.kill) ## killall pattern
    gevent.signal(signal.SIGQUIT, evt.set)
    gevent.signal(signal.SIGTERM, evt.set)
    gevent.signal(signal.SIGINT, evt.set)
    evt.wait()

    # finally stop
    app.stop()
