from gevent.queue import Queue
from collections import OrderedDict
from pyethereum import rlp
import struct

"""
Questions:
    packet_type length and endcoding (bigendian signed?)    : preliminary YES
    is data in the payload really wrapped into rlp?         : preliminary YES
    how is a packet build (cmd_id, rlp(payload))?           : preliminary Packet
    total-packet-size == total_payload_size ???             : preliminary YES

Improvements:
    use memoryview
    tests
"""



class Frame(object):
    """
    When sending a packet over RLPx, the packet will be framed.
    The frame provides information about the size of the packet and the packet's
    source protocol. There are three slightly different frames, depending on whether
    or not the frame is delivering a multi-frame packet. A multi-frame packet is a
    packet which is split (aka chunked) into multiple frames because it's size is
    larger than the protocol window size (pws; see Multiplexing). When a packet is
    chunked into multiple frames, there is an implicit difference between the first
    frame and all subsequent frames.
    Thus, the three frame types are
    normal, chunked-0 (first frame of a multi-frame packet),
    and chunked-n (subsequent frames of a multi-frame packet).


    Single-frame packet:
    header || header-mac || frame || mac

    Multi-frame packet:
    header || header-mac || frame-0 ||
    [ header || header-mac || frame-n || ... || ]
    header || header-mac || frame-last || mac
    """

    header_size = 16
    header_mac_size = 16
    payload_mac_size = 32
    frame_base_size = header_size + header_mac_size + payload_mac_size
    is_chunked_0 = False
    total_payload_size = None  # only used with chunked_0

    def __init__(self, protocol_id, cmd_id, payload, sequence_id, window_size,
                 is_chunked_n=False, frames=None):
        assert isinstance(window_size, int)
        assert isinstance(cmd_id, int) and cmd_id < 256
        self.cmd_id = cmd_id
        self.payload = payload
        self.frames = frames or []
        assert protocol_id < 2**16
        self.protocol_id = protocol_id
        assert sequence_id is None or sequence_id < 2**16
        self.sequence_id = sequence_id
        self.is_chunked_n = is_chunked_n
        self.frames.append(self)

        # chunk payloads resulting in frames exceeding window_size
        fs = self.frame_size()
        if fs > window_size:
            if not is_chunked_n:
                self.is_chunked_0 = True
                self.total_payload_size = len(payload)
            # chunk payload
            self.payload = payload[:window_size-fs]
            remain = payload[len(self.payload):]
            assert len(remain) + len(self.payload) == len(payload)
            assert self.frame_size() <= window_size
            Frame(protocol_id, cmd_id, remain, sequence_id+1, window_size,
                  is_chunked_n=True,
                  frames=self.frames)

    def __repr__(self):
        return '<Frame(%s, len=%d sid=%r)>' % \
                (self._frame_type(), self.frame_size(), self.sequence_id)

    def _frame_type(self):
        return 'normal' * self.is_normal or 'chunked_0' * self.is_chunked_0 or 'chunked_n'

    def frame_size(self, data_len=0):
        # header16 || mac16 || dataN || mac32
        return self.frame_base_size + (data_len or len(self.body))

    @property
    def is_normal(self):
        return not self.is_chunked_n and not self.is_chunked_0

    @property
    def header(self):
        """
        header: frame-size || header-data || padding
        frame-size: 3-byte integer size of frame, big endian encoded
        header-data:
            normal, chunked-n: rlp.list(protocol-type[, sequence-id])
            chunked-0: rlp.list(protocol-type, sequence-id, total-packet-size)
            values:
                protocol-type: < 2**16
                sequence-id: < 2**16 (this value is optional for normal frames)
                total-packet-size: < 2**32
        padding: zero-fill to 16-byte boundary
        """
        def i16(_int):
            return struct.pack('>I', _int)[2:]

        assert self.protocol_id < 2**16
        assert self.sequence_id is None or self.sequence_id < 2**16
        l = [i16(self.protocol_id)]
        if self.is_chunked_0:
            assert self.sequence_id is not None
            l.append(i16(self.sequence_id))
            l.append(struct.pack('>I', self.total_payload_size))
        elif self.sequence_id:  # normal, chunked_n
                l.append(i16(self.sequence_id))
        header_data = rlp.encode(l)
        frame_size = self.frame_size()
        assert frame_size < 256**3
        header = struct.pack('>I', frame_size)[1:] + header_data
        header += '\x00' * (self.header_size - len(header))
        return header

    @property
    def body(self):
        """
        packet:
        normal, chunked-0: rlp(packet-type) [|| rlp(packet-data)] || padding
        chunked-n: packet-data || padding

        padding: zero-fill to 16-byte boundary

        Q: rlp(data) or rlp_data
        """
        b = ''
        # packet-type
        if not self.is_chunked_n:
            b += rlp.encode(struct.pack("B", self.cmd_id))  # unsigned byte
            # payload
            b += rlp.encode(self.payload)
        else:
            b += self.payload
        # padding
        if len(b) % 16:
            b += '\0' * (1 - len(b) % 16)
        return b

    def get_frames(self):
        return self.frames

    def to_string(self):
        return self.header + self.body


class Packet(object):
    """
    Packets are emitted and received by subprotocols
    """

    def __init__(self, protocol_id=0, cmd_id=0, payload='', prioritize=False):
        self.protocol_id = protocol_id
        self.cmd_id = cmd_id
        self.payload = payload
        self.prioritize = prioritize

    def __repr__(self):
        return 'Packet(%r)' % dict(protocol_id=self.protocol_id,
                                   cmd_id=self.cmd_id,
                                   payload_len=len(self.payload),
                                   prioritize=self.prioritize)

    def __eq__(self, other):
        s = dict(self.__dict__)
        s.pop('prioritize')
        o = dict(other.__dict__)
        o.pop('prioritize')
        return s == o


class Multiplexer(object):
    """
    Multiplexing of protocols is performed via dynamic framing and fair queueing.
    Dequeuing packets is performed in a cycle which dequeues one or more packets
    from the queue(s) of each active protocol. The multiplexor determines the
    amount of bytes to send for each protocol prior to each round of dequeuing packets.

    If the size of an RLP-encoded packet is less than 1 KB then the protocol may
    request that the network layer prioritize the delivery of the packet.
    This should be used if and only if the packet must be delivered before all other packets.
    The network layer maintains two queues and three buffers per protocol:
    a queue for normal packets, a queue for priority packets,
    a chunked-frame buffer, a normal-frame buffer, and a priority-frame buffer.


    Implemented Variant:

    each sub protocol has three queues
        prio
        normal
        chunked

    protocols are queried round robin

    """

    max_window_size = 8*1024
    max_priority_frame_size = 1024

    def __init__(self):
        self.queues = OrderedDict()  # protocol_id : dict(normal=queue, chunked=queue, prio=queue)
        self.sequence_id = 0
        self.last_protocol = None  # last protocol, which sent data to the buffer
        self.chunked_buffers = dict()  # decode: next_expected_sequence_id > buffer


    @property
    def num_active_protocols(self):
        "A protocol is considered active if it's queue contains one or more packets."
        return sum(1 for p_id in self.queues if self.is_active_protocol(p_id))

    def is_active_protocol(self, protocol_id):
        return True if sum(q.qsize() for q in self.queues[protocol_id].values()) else False

    def protocol_window_size(self, protocol_id=None):
        """
        pws = protocol-window-size = window-size / active-protocol-count
        initial pws = 8kb
        """
        if protocol_id and not self.is_active_protocol(protocol_id):
            return self.max_window_size / (1 + self.num_active_protocols)
        else:
            return self.max_window_size / max(1, self.num_active_protocols)

    def add_protocol(self, protocol_id):
        assert protocol_id not in self.queues
        self.queues[protocol_id] = dict(normal=Queue(),
                                        chunked=Queue(),
                                        priority=Queue())
        self.last_protocol = protocol_id

    @property
    def next_protocol(self):
        protocols = self.queues.keys()
        if self.last_protocol == protocols[-1]:
            next_protocol = protocols[0]
        else:
            next_protocol = protocols[protocols.index(self.last_protocol) + 1]
        self.last_protocol = next_protocol
        return next_protocol

    def add_packet(self, packet):
        #protocol_id, cmd_id, rlp_data, prioritize=False
        frames = Frame(packet.protocol_id, packet.cmd_id, packet.payload,
                       sequence_id=self.sequence_id,
                       window_size=self.protocol_window_size(packet.protocol_id)
                       ).frames
        self.sequence_id = frames[-1].sequence_id + 1
        queues = self.queues[packet.protocol_id]
        if packet.prioritize:
            assert len(frames) == 1
            assert frames[0].frame_size() <= self.max_priority_frame_size
            queues['priority'].put(frames[0])
        elif len(frames) == 1:
            queues['normal'].put(frames[0])
        else:
            for f in frames:
                queues['chunked'].put(f)


    def pop_frames_for_protocol(self, protocol_id):
        """
        If priority packet and normal packet exist:
            send up to pws/2 bytes from each (priority first!)
        else if priority packet and chunked-frame exist:
            send up to pws/2 bytes from each
        else
            if normal packet and chunked-frame exist: send up to pws/2 bytes from each
        else
            read pws bytes from active buffer

        If there are bytes leftover -- for example, if the bytes sent is < pws,
            then repeat the cycle.
        """

        pws = self.protocol_window_size()
        queues = self.queues[protocol_id]
        frames = []
        # size = lambda:
        size = 0
        while size < pws:
            frames_added = 0
            for qn in ('priority', 'normal', 'chunked'):
                q = queues[qn]
                if q.qsize():
                    fs = q.peek().frame_size()
                    if size + fs <= pws:
                        frames.append(q.get())
                        size += fs
                        frames_added += 1
                # add no more than two in order to send normal and priority first
                if frames_added == 2:
                    break  # i.e. next is 'priority' again
            # empty queues
            if frames_added == 0:
                break
        # the following can not be guaranteed, as pws might have been different
        # at the time where packets were framed and added to the queues
        # assert sum(f.frame_size() for f in frames) <= pws
        return frames

    def pop_frames(self):
        protocols = self.queues.keys()
        idx = protocols.index(self.next_protocol)
        protocols = protocols[idx:] + protocols[:idx]
        assert len(protocols) == len(self.queues.keys())
        for p in protocols:
            frames = self.pop_frames_for_protocol(p)
            if frames:
                return frames
        return []

    def pop_all_frames(self):
        frames = []
        while True:
            r = self.pop_frames()
            frames.extend(r)
            if not r:
                break
        return frames

    def pop_all_frames_as_bytes(self):
        return ''.join(f.to_string() for f in self.pop_all_frames())

    def decode_frame(self, buffer):
        """
        w/o encryption
        peak into buffer for frame_size

        return None if buffer is not long enough to decode frame
        """

        if len(buffer) < Frame.header_size:
            return None, buffer

        def d16(data):
            return struct.unpack('>I', '\x00\x00' + data)[0]

        def garbage_collect(protocol_id):
            """
            chunked packets of a sub protocol are send in order
            thus if a new frame_0 of a subprotocol is received others must be removed
            """
            for sid, packet in self.chunked_buffers.items():
                if packet.protocol_id == protocol_id:
                    del self.chunked_buffers[sid]

        # header: frame-size || header-data || padding
        # frame-size: 3-byte integer size of frame, big endian encoded
        frame_size = struct.unpack('>I', '\x00' + buffer[:3])[0]

        # FIXME: frames are calculated with MACs, which we don't have yet
        real_no_mac_frame_size = frame_size - 16 - 32
        remain = buffer[real_no_mac_frame_size:]
        if len(buffer) < real_no_mac_frame_size:
            return None, buffer
        buffer = buffer[:real_no_mac_frame_size]
        # END FIXME

        header_data = rlp.decode(buffer[3:Frame.header_size])
        # normal, chunked-n: rlp.list(protocol-type[, sequence-id])
        # chunked-0: rlp.list(protocol-type, sequence-id, total-packet-size)

        if len(header_data) == 3:
            chunked_0 = True
            # total-packet-size: < 2**32
            total_payload_size = struct.unpack('>I', header_data[2])[0]
        else:
            chunked_0 = False
            total_payload_size = None

        # protocol-type: < 2**16
        protocol_id = d16(header_data[0])
        # sequence-id: < 2**16 (this value is optional for normal frames)
        if len(header_data) > 1:
            sequence_id = d16(header_data[1])
        else:
            sequence_id = None

        # build packet
        body_offset = Frame.header_size
        if sequence_id in self.chunked_buffers:
            # body chunked-n: packet-data || padding
            packet = self.chunked_buffers.pop(sequence_id)
            packet.payload += buffer[body_offset:]
            if packet.total_payload_size == len(packet.payload):
                del packet.total_payload_size
                return packet, remain
            self.chunked_buffers[sequence_id + 1] = packet
        else:
            # body normal, chunked-0: rlp(packet-type) [|| rlp(packet-data)] || padding
            cmd_id = rlp.big_endian_to_int(rlp.decode(buffer[body_offset]))
            packet = Packet(protocol_id=protocol_id,
                            cmd_id=cmd_id,
                            payload=rlp.decode(buffer[body_offset+1:]))
            if chunked_0:
                garbage_collect(protocol_id)
                assert sequence_id
                packet.total_payload_size = total_payload_size
                self.chunked_buffers[sequence_id + 1] = packet
            else:  # normal
                return packet, remain
        return None, remain  # for chunked, not finished data

    def decode_frames(self, buffer):
        packets = []
        remain = last_remain = buffer
        while True:
            packet, remain = self.decode_frame(remain)
            if packet:
                packets.append(packet)
            elif remain == last_remain:
                break
            last_remain = remain
        return packets, remain


if __name__ == '__main__':
    import sys

    mux = Multiplexer()
    p0, p1, p2 = 0, 1, 2
    mux.add_protocol(p0)
    mux.add_protocol(p1)
    mux.add_protocol(p2)

    assert mux.next_protocol == p0
    assert mux.next_protocol == p1
    assert mux.next_protocol == p2
    assert mux.next_protocol == p0

    assert mux.pop_frames() == []
    assert mux.num_active_protocols == 0

    def pws():
        print 'pws', mux.protocol_window_size(), 'n active', mux.num_active_protocols


    # test normal packet
    packet0 = Packet(p0, cmd_id=0, payload='\x00' * 100)

    mux.add_packet(packet0)
    assert mux.num_active_protocols == 1

    frames = mux.pop_frames()
    assert len(frames) == 1
    f = frames[0]
    assert len(f.to_string()) == f.frame_size() - 32 - 16

    mux.add_packet(packet0)
    assert mux.num_active_protocols == 1
    message = mux.pop_all_frames_as_bytes()
    packets, remain = mux.decode_frames(message)
    assert packets[0] == packet0

    # nothing left to pop
    assert len(mux.pop_frames()) == 0

    packet1 = Packet(p1, cmd_id=0, payload='\x00' * mux.max_window_size * 2)
    mux.add_packet(packet1)

    # decode packets from buffer
    message = mux.pop_all_frames_as_bytes()
    packets, remain = mux.decode_frames(message)
    assert packets[0].payload == packet1.payload
    assert packets[0] == packet1
    assert len(packets) == 1

    # mix packet types
    packet2 = Packet(p0, cmd_id=0, payload='\x00' * 200, prioritize=True)
    mux.add_packet(packet1)
    mux.add_packet(packet0)
    mux.add_packet(packet2)
    message = mux.pop_all_frames_as_bytes()
    packets, remain = mux.decode_frames(message)
    assert packets == [packet2, packet0, packet1]

    # packets with different protocols
    packet3 = Packet(p1, cmd_id=0, payload='\x00' * 3000, prioritize=False)
    mux.add_packet(packet1)
    mux.add_packet(packet0)
    mux.add_packet(packet2)
    mux.add_packet(packet3)
    mux.add_packet(packet3)
    mux.add_packet(packet3)
    assert mux.next_protocol == p0
    # thus next with data is p1 w/ packet3
    message = mux.pop_all_frames_as_bytes()
    packets, remain = mux.decode_frames(message)
    assert packets == [packet3, packet2, packet0, packet3, packet3, packet1]

    # test buffer remains, incomplete frames
    packet1 = Packet(p1, cmd_id=0, payload='\x00' * 100)
    mux.add_packet(packet1)
    message = mux.pop_all_frames_as_bytes()
    tail = message[:50]
    message += tail
    packets, remain = mux.decode_frames(message)
    assert packets[0] == packet1
    assert len(packets) == 1
    assert len(remain) == len(tail)

    # test buffer decode with invalid data
    message = message[1:]
    packets, remain = mux.decode_frames(message)

