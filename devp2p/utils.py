import struct
import rlp
import collections

ienc = int_to_big_endian = rlp.sedes.big_endian_int.serialize


def big_endian_to_int(s):
    return rlp.sedes.big_endian_int.deserialize(s.lstrip('\x00'))

idec = big_endian_to_int


def int_to_big_endian4(integer):
    ''' 4 bytes big endian integer'''
    return struct.pack('>I', integer)

ienc4 = int_to_big_endian4


node_uri_scheme = 'enode://'


def host_port_pubkey_from_uri(uri):  # FIXME pubkey will be nodeid
    assert uri.startswith(node_uri_scheme) and '@' in uri and ':' in uri
    pubkey_hex, ip_port = uri[len(node_uri_scheme):].split('@')
    assert len(pubkey_hex) == 2 * 512 / 8
    ip, port = ip_port.split(':')
    return ip, port, pubkey_hex.decode('hex')


def host_port_pubkey_to_uri(host, port, pubkey):
    return '%s%s@%s:%d' % (node_uri_scheme, pubkey.encode('hex'),
                           host, port)


# ###### config helpers ###############

def hex_decode_config(self):
    def _with_dict(d):
        "recursively search and decode hex encoded data"
        for k, v in d.items():
            if k.endswith('_hex'):
                d[k[:-len('_hex')]] = v.decode('hex')
            if isinstance(v, dict):
                _with_dict(v)
    _with_dict(self.config)


def update_config_with_defaults(config, default_config):
    for k, v in default_config.iteritems():
        if isinstance(v, collections.Mapping):
            r = update_config_with_defaults(config.get(k, {}), v)
            config[k] = r
        elif k not in config:
            config[k] = default_config[k]
    return config
