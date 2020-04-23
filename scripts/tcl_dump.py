#!/usr/bin/env python
import struct
import sys
import os
import time

PATH_DEV_RQST = '/sys/bus/serial/devices/serial0-0/rqst'


def pack_block_data(id, offset, size, end):
    return struct.pack('<HIHB', id, offset, size, end)


def unpack_block_data(buf):
    return struct.unpack('<HIHB', buf)


def unpack_buffer(buf):
    return unpack_block_data(buf[:9]), buf[9:]


def build_command(iid, buf_id, offset, size):
    command = bytes([0x0c, 0x0c, iid, 0x01, 0x01, 0x09])
    data = pack_block_data(buf_id, offset, size, 0)
    return command + data


def main():
    buf_id = 2
    iid = 1

    offset = 0
    readlen = 0x20
    buffer = bytes()
    while True:
        fd = os.open(PATH_DEV_RQST, os.O_RDWR | os.O_SYNC)
        try:
            print(f"reading {offset}:{readlen}")
            os.write(fd, build_command(iid, buf_id, offset, readlen))
        except IOError:
            time.sleep(4)
            continue

        os.lseek(fd, 0, os.SEEK_SET)
        length = os.read(fd, 1)[0]
        data = os.read(fd, length)
        os.close(fd)

        (_, _, nread, end), bufdata = unpack_buffer(data)
        print(f"read {offset}:{nread}")
        buffer += bufdata
        offset += nread

        if end != 0:
            break

    out = open(f"tclbuf_iid{iid}_bufid{buf_id}.bin", "wb")
    out.write(buffer)


if __name__ == '__main__':
    main()
