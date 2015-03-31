import struct
import collections


def int_to_big_endian(integer):
    '''convert a integer to big endian binary string'''
    # 0 is a special case, treated same as ''
    if integer == 0:
        return ''
    s = '%x' % integer
    if len(s) & 1:
        s = '0' + s
    return s.decode('hex')

ienc = int_to_big_endian


def big_endian_to_int(string):
    '''convert a big endian binary string to integer'''
    # '' is a special case, treated same as 0
    s = string.encode('hex') or '0'
    return long(s, 16)
idec = big_endian_to_int


def recursive_int_to_big_endian(item):
    ''' convert all int to int_to_big_endian recursively
    '''
    if isinstance(item, (int, long)):
        return ienc(item)
    elif isinstance(item, (list, tuple)):
        res = []
        for item in item:
            res.append(recursive_int_to_big_endian(item))
        return res
    return item


def int_to_big_endian4(integer):
    ''' 4 bytes big endian integer'''
    return struct.pack('>I', integer)

ienc4 = int_to_big_endian4


def update_with_defaults(config, default_config):
    for k, v in default_config.iteritems():
        if isinstance(v, collections.Mapping):
            r = update_with_defaults(config.get(k, {}), v)
            config[k] = r
        elif k not in config:
            config[k] = default_config[k]
    return config
