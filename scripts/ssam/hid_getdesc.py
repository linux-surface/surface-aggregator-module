#!/usr/bin/env python3
from __future__ import print_function
import sys
import json

import libssam
from libssam import Controller, Request


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def u32le_to_buf(val):
    return [val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff]


def buf_to_u32le(buf):
    return buf[0] | (buf[1] >> 8) | (buf[2] >> 16) | (buf[3] >> 24)


def query_buffer_part(ctrl, tc, tid, cid, iid, bufid, offset, length):
    payload = [bufid] + u32le_to_buf(offset) + u32le_to_buf(length) + [0x00]
    command = Request(tc, tid, cid, iid, libssam.REQUEST_HAS_RESPONSE, payload,
                      128)

    return ctrl.request(command)


def query_buffer(ctrl, tc, tid, cid, iid, bufid):
    length = 0x76
    offset = 0x00
    buffer = bytearray()

    while True:
        data = query_buffer_part(ctrl, tc, tid, cid, iid, bufid, offset, length)
        returned = buf_to_u32le(data[5:9])

        offset += returned
        buffer += data[10:]

        if data[9] == 1 or returned == 0:
            return buffer


def main():
    requests = [
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x00, "bufid": 0x00},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x00, "bufid": 0x01},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x00, "bufid": 0x02},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x00, "bufid": 0x03},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x01, "bufid": 0x00},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x01, "bufid": 0x01},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x01, "bufid": 0x02},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x01, "bufid": 0x03},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x02, "bufid": 0x00},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x02, "bufid": 0x01},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x02, "bufid": 0x02},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x02, "bufid": 0x03},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x03, "bufid": 0x00},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x03, "bufid": 0x01},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x03, "bufid": 0x02},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x03, "bufid": 0x03},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x04, "bufid": 0x00},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x04, "bufid": 0x01},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x04, "bufid": 0x02},
        {"tc": 0x15, "tid": 0x02, "cid": 0x04, "iid": 0x04, "bufid": 0x03},
    ]

    with Controller() as ctrl:
        output = []
        for rq in requests:
            try:
                data = query_buffer(ctrl, **rq)

                rq["response"] = [x for x in data]
                output += [rq]
            except OSError as e:
                eprint(f"Failed to execute request: {rq} ({e})")

    print(json.dumps(output))


if __name__ == '__main__':
    main()
