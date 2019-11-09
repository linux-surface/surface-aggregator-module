#!/usr/bin/env python3
from __future__ import print_function
import sys
import os
import json

PATH_DEV_RQST = '/sys/bus/serial/devices/serial0-0/rqst'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def u32le_to_buf(val):
    return [val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff]


def buf_to_u32le(buf):
    return buf[0] | (buf[1] >> 8) | (buf[2] >> 16) | (buf[3] >> 24)


def query(command):
    fd = os.open(PATH_DEV_RQST, os.O_RDWR | os.O_SYNC)
    try:
        os.write(fd, bytes(command))

        os.lseek(fd, 0, os.SEEK_SET)
        length = os.read(fd, 1)[0]
        data = os.read(fd, length)
    finally:
        os.close(fd)

    return data


def query_buffer_part(tc, cid, iid, pri, bufid, offset, length):
    payload = [bufid] + u32le_to_buf(offset) + u32le_to_buf(length) + [0x00]
    command = [tc, cid, iid, pri, 0x01, len(payload)] + payload

    return query(command)


def query_buffer(tc, cid, iid, pri, bufid):
    length = 0x76
    offset = 0x00
    buffer = bytearray()

    while True:
        data = query_buffer_part(tc, cid, iid, pri, bufid, offset, length)
        returned = buf_to_u32le(data[5:9])

        offset += returned
        buffer += data[10:]

        if data[9] == 1 or returned == 0:
            return buffer


def main():
    requests = [
        {"tc": 0x15, "cid": 0x04, "iid": 0x00, "pri": 0x02, "bufid": 0x00},
        {"tc": 0x15, "cid": 0x04, "iid": 0x00, "pri": 0x02, "bufid": 0x01},
        {"tc": 0x15, "cid": 0x04, "iid": 0x00, "pri": 0x02, "bufid": 0x02},
        {"tc": 0x15, "cid": 0x04, "iid": 0x00, "pri": 0x02, "bufid": 0x03},
    ]

    output = []
    for rq in requests:
        try:
            data = query_buffer(**rq)

            rq["response"] = [x for x in data]
            output += [rq]
        except OSError:
            eprint(f"Failed to execute request: {rq}")

    print(json.dumps(output))


if __name__ == '__main__':
    main()
