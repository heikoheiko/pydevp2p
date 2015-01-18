import sys
from devp2p.multiplexer import Multiplexer, Packet


def test_multiplexer():
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

