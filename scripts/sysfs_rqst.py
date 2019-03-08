#!/usr/bin/env python3
import sys
import os


# commands       [  TC,  IID,  CID,  SNC,  CDL]
# detach lock    [0x11, 0x00, 0x06, 0x00, 0x00]
# detach unlock  [0x11, 0x00, 0x07, 0x00, 0x00]
# detach abort   [0x11, 0x00, 0x08, 0x00, 0x00]
# detach ack     [0x11, 0x00, 0x09, 0x00, 0x00]


def main(path):
    fd = os.open(path, os.O_RDWR | os.O_SYNC)

    #            [  TC,  IID,  CID,  SNC,  CDL]
    data = bytes([0x11, 0x00, 0x09, 0x00, 0x00])

    os.write(fd, data)
    data = os.read(fd, 255)

    os.close(fd)

    print(data)


if __name__ == '__main__':
    main(sys.argv[1])
