#!/usr/bin/env python3
import sys
import os

PATH_DEV_RQST = '/sys/bus/serial/devices/serial0-0/rqst'


# commands       [  TC,  CID,  IID,  PRI,  SNC,  CDL]
# detach lock    [0x11, 0x06, 0x00, 0x01, 0x00, 0x00]
# detach unlock  [0x11, 0x07, 0x00, 0x01, 0x00, 0x00]
# detach abort   [0x11, 0x08, 0x00, 0x01, 0x00, 0x00]
# detach ack     [0x11, 0x09, 0x00, 0x01, 0x00, 0x00]

def performance_state_request(state):
    return bytes([0x03, 0x03, 0x00, 0x01, 0x00, 0x04, state, 0x00, 0x00, 0x00])


def main():
    fd = os.open(PATH_DEV_RQST, os.O_RDWR | os.O_SYNC)

    #            [  TC,  CID,  IID,  PRI,  SNC,  CDL, payload...]
    data = bytes(performance_state_request(state=0x04))

    os.write(fd, data)

    os.lseek(fd, 0, os.SEEK_SET)
    length = os.read(fd, 1)[0]
    data = os.read(fd, length)

    os.close(fd)

    print(' '.join(['{:02x}'.format(x) for x in data]))


if __name__ == '__main__':
    main()
