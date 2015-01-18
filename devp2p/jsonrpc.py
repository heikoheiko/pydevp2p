#!/usr/bin/env python
# -*- coding: utf-8 -*-
# https://github.com/robnewton/JSON-RPC-Browser

import gevent
import gevent.wsgi
import gevent.queue
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.wsgi import WsgiServerTransport
from tinyrpc.server.gevent import RPCServerGreenlets
from tinyrpc.dispatch import RPCDispatcher
from service import BaseService
import slogging
log = slogging.get_logger('jsonrpc')


class JSONRPCServer(BaseService):

    name = 'jsonrpc'

    def __init__(self, app):
        log.debug('initializing JSONRPCServer')
        BaseService.__init__(self, app)
        self.app = app
        self.dispatcher = RPCDispatcher()
        transport = WsgiServerTransport(queue_class=gevent.queue.Queue)

        # start wsgi server as a background-greenlet
        self.wsgi_server = gevent.wsgi.WSGIServer(('127.0.0.1', 5000), transport.handle)

        self.rpc_server = RPCServerGreenlets(
            transport,
            JSONRPCProtocol(),
            self.dispatcher
        )

    def _run(self):
        log.info('starting JSONRPCServer')
        # in the main greenlet, run our rpc_server
        self.wsgi_thread = gevent.spawn(self.wsgi_server.serve_forever)
        self.rpc_server.serve_forever()

    def add_method(self, func, name=None):
        self.dispatcher.add_method(func, name)

    def stop(self):
        log.info('stopping JSONRPCServer')
        self.wsgi_thread.kill()

if __name__ == '__main__':

    def reverse_string(s):
        return s[::-1]

    server = JSONRPCServer(app=None)
    server.add_method(reverse_string)
    server.start()
#    server._run()
    e = gevent.event.Event()
    e.wait()
