===============================
pydevp2p
===============================

.. image:: https://badge.fury.io/py/devp2p.png
    :target: http://badge.fury.io/py/devp2p

.. image:: https://travis-ci.org/heikoheiko/pydevp2p.png?branch=master
        :target: https://travis-ci.org/heikoheiko/pydevp2p

.. image:: https://coveralls.io/repos/heikoheiko/pydevp2p/badge.svg
        :target: https://coveralls.io/r/heikoheiko/pydevp2p

.. image:: https://pypip.in/d/devp2p/badge.png
        :target: https://pypi.python.org/pypi/devp2p

.. image:: https://readthedocs.org/projects/pydevp2p/badge/?version=latest
        :target: https://readthedocs.org/projects/pydevp2p/?badge=latest


Python implementation of the Ethereum P2P stack

* Free software: BSD license
* Documentation: https://pydevp2p.readthedocs.org.

Introduction
------------

pydevp2p is the Python implementation of the RLPx network layer.
RLPx provides a general-purpose transport and interface for applications to communicate via a p2p network. The first version is geared towards building a robust transport, well-formed network, and software interface in order to provide infrastructure which meets the requirements of distributed or decentralized applications such as Ethereum. Encryption is employed to provide better privacy and integrity than would be provided by a cleartext implementation.

RLPx underpins the DEVp2p interface:

* https://github.com/ethereum/wiki/wiki/ÐΞVp2p-Wire-Protocol
* https://github.com/ethereum/wiki/wiki/libp2p-Whitepaper

Full spec:

* https://github.com/ethereum/devp2p/blob/master/rlpx.md

Features
--------
* Node Discovery and Network Formation
* Peer Preference Strategies
* Peer Reputation
* Multiple protocols
* Encrypted handshake
* Encrypted transport
* Dynamically framed transport
* Fair queuing

Security Overview
-------------------
* nodes have access to a uniform network topology
* peers can uniformly connect to network
* network robustness >= kademlia
* protocols sharing a connection are provided uniform bandwidth
* authenticated connectivity
* authenticated discovery protocol
* encrypted transport (TCP now; UDP in future)
* robust node discovery
