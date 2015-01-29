import rlp
from utils import idec
from utils import ienc4
from utils import recursive_int_to_big_endian
from slogging import get_logger
log = get_logger('serialization')


def lrlp_decode(data):
    "always return a list"
    d = rlp.decode(data)
    if isinstance(d, str):
        d = [d]
    return d


class Serializer(object):

    disconnect_reasons_map = dict((
        ('Disconnect requested', 0x00),
        ('TCP sub-system error', 0x01),
        ('Bad protocol', 0x02),
        ('Useless peer', 0x03),
        ('Too many peers', 0x04),
        ('Already connected', 0x05),
        ('Wrong genesis block', 0x06),
        ('Incompatible network protocols', 0x07),
        ('Client quitting', 0x08)))

    disconnect_reasons_map_by_id = \
        dict((v, k) for k, v in disconnect_reasons_map.items())

    @classmethod
    def packet_size(cls, packet):
        return idec(packet[4:8]) + 8

    @classmethod
    def packet_cmd(cls, packet):
        try:
            v = idec(rlp.descend(packet[8:200], 0))
        except rlp.DecodingError:
            v = -1
        return v

    @classmethod
    def load_packet(cls, packet):
        '''
        Though TCP provides a connection-oriented medium, Ethereum nodes
        communicate in terms of packets. These packets are formed as a 4-byte
        synchronisation token (0x22400891), a 4-byte "payload size", to be
        interpreted as a big-endian integer and finally an N-byte
        RLP-serialised data structure, where N is the aforementioned
        "payload size". To be clear, the payload size specifies the number of
        bytes in the packet ''following'' the first 8.

        :return: (success, result), where result should be None when fail,
        and (header, payload_len, cmd, data) when success
        '''
        header = idec(packet[:4])
        if header != cls.SYNCHRONIZATION_TOKEN:
            return dict(error='check header failed, skipping message,'
                              'sync token was hex: %s' % hex(header))

        try:
            payload_len = idec(packet[4:8])
        except Exception as e:
            return dict(error=str(e))

        if len(packet) < payload_len + 8:
            return dict(error='packet wrong length')

        try:
            payload = lrlp_decode(packet[8:8 + payload_len])
        except Exception as e:
            return dict(error=str(e))

        if (not len(payload)) or (idec(payload[0]) not in cls.cmd_map):
            return dict(error='check cmd %r failed' % idec(payload[0]))

        cmd_id = idec(payload[0])
        remain = packet[8 + payload_len:]
        return dict(header=header,
                    payload_len=payload_len,
                    cmd_id=cmd_id,
                    data=payload[1:],
                    remain=remain)

    @classmethod
    def dump_packet(cls, data):
        """
        4-byte synchronisation token, (0x22400891),
        a 4-byte "payload size", to be interpreted as a big-endian integer
        an N-byte RLP-serialised data structure
        """
        payload = rlp.encode(recursive_int_to_big_endian(data))
        packet = ienc4(cls.SYNCHRONIZATION_TOKEN)
        packet += ienc4(len(payload))
        packet += payload
        return packet
