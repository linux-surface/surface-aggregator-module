#!/usr/bin/env python

import sys
import re
import json

from dataclasses import dataclass


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


@dataclass
class FrameCtrl:
    type: int
    len: int
    pad: int
    seq: int

    def __str__(self):
        return f"type: {hex(self.type)}, len: {hex(self.len)}, pad: {hex(self.pad)}, " + \
               f"seq: {hex(self.seq)}"

    def to_dict(self):
        return {
            "type": self.type,
            "len": self.len,
            "pad": self.pad,
            "seq": self.seq,
        }


@dataclass
class FrameCmd:
    type: int
    tc: int
    sid: int
    tid: int
    iid: int
    rqid: int
    cid: int

    def __str__(self):
        return f"type: {hex(self.type)}, tc: {hex(self.tc)}, tid: {hex(self.tid)}, " + \
               f"sid: {hex(self.sid)}, iid: {hex(self.iid)}, rqid: {hex(self.rqid)}, " + \
               f"cid: {hex(self.cid)}"

    def to_dict(self):
        return {
            "type": self.type,
            "tc": self.tc,
            "sid": self.sid,
            "tid": self.tid,
            "iid": self.iid,
            "rqid": self.rqid,
            "cid": self.cid,
        }


def index(file):
    # TODO: handle TX as well...
    re_ts = re.compile(r"""
        ^\[                         # braces around timestamp
            (?P<ts>                 # actual timestamp
                [0-9]+
                \.
                [0-9]+
            )
        \]
        \s
        rx:                         # rx data dump
        \s
        [0-9a-fA-F]+:
        (?P<bytes>                  # match all data bytes
            (
                \s
                (
                    [0-9a-fA-F]
                    [0-9a-fA-F]
                )
            )+
        )
    """, re.VERBOSE)

    with open(file) as fd:
        lines = [line.strip() for line in fd]

    timestamps = []
    data = bytes()

    for line in lines:
        match = re_ts.match(line)

        if match is None:
            continue

        groups = match.groupdict()
        ts = float(groups["ts"])
        bt = bytes([int(x, base=16) for x in groups["bytes"].split()])

        timestamps += [(ts, len(data), len(data) + len(bt))]
        data += bt

    return data, timestamps


def find_timestamp(timestamps, index):
    for (ts, a, b) in timestamps:
        if a <= index < b:
            return ts


def parse_syn(data):
    if data[0:2] != bytes([0xaa, 0x55]):
        eprint("warning: expected SYN, skipping data until next SYN")

        for i in range(1, len(data)):
            if data[i] == 0xaa and data[i+1] == 0x55:
                eprint("data dropped: " + ' '.join(map(hex, data[:i])))
                return data[i+2:]

    return data[2:]


def parse_checksum(data):
    return data[2:]


def parse_frame_ctrl(data):
    ty = data[0]
    len = data[1]
    pad = data[2]
    seq = data[3]

    return data[4:], FrameCtrl(ty, len, pad, seq)


def parse_frame_cmd(data):
    ty = data[0]
    tc = data[1]
    out = data[2]
    inc = data[3]
    iid = data[4]
    rqid_lo = data[5]
    rqid_hi = data[6]
    cid = data[7]

    rqid = rqid_hi << 8 | rqid_lo

    return data[8:], FrameCmd(ty, tc, out, inc, iid, rqid, cid)


def parse_data(data, timestamps):
    records = []

    total = len(data)
    while data:
        data = parse_syn(data)
        data, ctrl = parse_frame_ctrl(data)
        data = parse_checksum(data)

        ts = find_timestamp(timestamps, total - len(data))

        if ctrl.type == 0x00 or ctrl.type == 0x80:
            data, cmd = parse_frame_cmd(data)

            payload_len = ctrl.len - 8
            data, pld = data[payload_len:], data[0:payload_len]

            data = parse_checksum(data)

            record = {"ctrl": ctrl.to_dict(), "cmd": cmd.to_dict(), "payload": list(pld), "time": ts}
            records.append(record)

        elif ctrl.type == 0x40:
            data = parse_checksum(data)
            records.append({"ctrl": ctrl.to_dict(), "time": ts})
        elif ctrl.type == 0x04:
            data = parse_checksum(data)
            records.append({"ctrl": ctrl.to_dict(), "time": ts})

    return records


def main():
    file = sys.argv[1]

    data, timestamps = index(file)
    print(json.dumps(parse_data(data, timestamps)))


if __name__ == '__main__':
    main()
