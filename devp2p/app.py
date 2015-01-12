from collections import UserDict
from service import BaseService
from slogging import get_logger
log = get_logger('app')


class BaseApp(object):

    def __init__(self, config):
        self.config = config
        self.services = UserDict()

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
        self._services.remove(service)
        delattr(self.services, service.name)

    def start(self):
        for service in self._services:
            service.start()

    def stop(self):
        for service in self._services:
            service.stop()


if __name__ == '__main__':
    # config
    import ConfigParser
    import io
    import sys
    import signal
    import gevent
    from peermanager import PeerManager
    from jsonrpc import JSONRPCServer

    import slogging
    log = slogging.get_logger('app')

    # read config
    sample_config = """
[p2p]
num_peers = 10
bootstrap_host = localhost
bootstrap_port = 30303
listen_host = 127.0.0.1
listen_port = 30302
    """
    config = ConfigParser.ConfigParser()
    if len(sys.argv) == 1:
        config.readfp(io.BytesIO(sample_config))
    else:
        fn = sys.argv[1]
        log.info('loading config from', fn=fn)
        config.readfp(open(fn))

    # create app
    app = BaseApp(config)

    # register services
    PeerManager.register_with_app(app)
    JSONRPCServer.register_with_app(app)

    # start app
    app.start()

    # wait for interupt
    evt = gevent.event.Event()
    gevent.signal(signal.SIGQUIT, evt.set)
    gevent.signal(signal.SIGTERM, evt.set)
    gevent.signal(signal.SIGINT, evt.set)
    evt.wait()

    # finally stop
    app.stop()
