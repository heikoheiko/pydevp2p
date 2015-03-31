#!/usr/bin/env python
from gevent import Greenlet
import utils


class BaseService(Greenlet):

    """
    service instances are added to the application under
    app.services.<service_name>

    app should be passed to the service in order to query other services

    services may be a greenlet or spawn greenlets.
    both must implement a .stop()
    if a services spawns additional greenlets, it's responsible to stop them.
    """

    name = ''
    default_config = {name: dict()}

    def __init__(self, app):
        Greenlet.__init__(self)
        self.app = app
        self.config = utils.update_with_defaults(app.config, self.default_config)

    def start(self):
        Greenlet.start(self)

    def stop(self):
        Greenlet.stop(self)

    @classmethod
    def register_with_app(klass, app):
        """
        services know best how to initiate themselfs.
        create a service instance, propably based on
        app.config and app.services
        """
        app.register_service(klass(app))
