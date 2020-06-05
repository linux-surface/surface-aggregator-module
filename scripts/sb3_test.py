#!/usr/bin/env python3
import sys
import os

PATH_DEV_RQST = '/sys/bus/serial/devices/serial0-0/rqst'


def lo16(rqid):
    return rqid & 0xff


def hi16(rqid):
    return (rqid >> 8) & 0xff


def enable_event(rqid, tc, iid, seq):
    #            [  TC,  CID,  IID,  PRI,  SNC,  CDL, payload...]
    return bytes([0x21, 0x01, 0x00, 0x02, 0x01, 0x05, tc, seq, lo16(rqid), hi16(rqid), iid])


def disable_event(rqid, tc, iid, seq):
    #            [  TC,  CID,  IID,  PRI,  SNC,  CDL, payload...]
    return bytes([0x21, 0x02, 0x00, 0x02, 0x01, 0x05, tc, seq, lo16(rqid), hi16(rqid), iid])


def sys_event_enable(rqid, tc, pri):
    #            [  TC,  CID,  IID,  PRI,  SNC,  CDL, payload...]
    return bytes([0x01, 0x0b, 0x00, 0x01, 0x01, 0x04, tc, pri, lo16(rqid), hi16(rqid)])


def sys_event_disable(rqid, tc, pri):
    #            [  TC,  CID,  IID,  PRI,  SNC,  CDL, payload...]
    return bytes([0x01, 0x0c, 0x00, 0x01, 0x01, 0x04, tc, pri, lo16(rqid), hi16(rqid)])


def main():
    if len(sys.argv) != 2:
        print("not a valid command: choose one of:")
        print("    setup, teardown, enable, disable")
        exit(1)

    cmd = sys.argv[1]
    if cmd == "setup":
        data = enable_event(0x21, 0x21, 0x00, 0x01)
    elif cmd == "teardown":
        data = disable_event(0x21, 0x21, 0x00, 0x01)
    elif cmd == "enable":
        data = enable_event(0x15, 0x15, 0x01, 0x00)
    elif cmd == "disable":
        data = disable_event(0x15, 0x15, 0x01, 0x00)
    elif cmd == "kbd-enable":
        data = sys_event_enable(0x15, 0x15, int(sys.argv[2], 0))
    elif cmd == "kbd-disable":
        data = sys_event_disable(0x15, 0x15, int(sys.argv[2], 0))
        pass
    else:
        print("not a valid command: choose one of:")
        print("    setup, teardown, enable, disable")
        exit(1)

    fd = os.open(PATH_DEV_RQST, os.O_RDWR | os.O_SYNC)
    os.write(fd, data)

    os.lseek(fd, 0, os.SEEK_SET)
    length = os.read(fd, 1)[0]
    data = os.read(fd, length)

    os.close(fd)

    print(' '.join(['{:02x}'.format(x) for x in data]))


if __name__ == '__main__':
    main()
