#!/usr/bin/env python3
import sys
import os

PATH_DEV_RQST = '/sys/bus/serial/devices/serial0-0/rqst'

EVCMDS = {
    'sam-enable':  {'chn': 1, 'tc': 0x01, 'cid': 0x0b, 'iid': 0x00, 'snc': 0x01},
    'sam-disable': {'chn': 1, 'tc': 0x01, 'cid': 0x0c, 'iid': 0x00, 'snc': 0x01},
    'kip-enable':  {'chn': 2, 'tc': 0x0e, 'cid': 0x27, 'iid': 0x00, 'snc': 0x01},
    'kip-disable': {'chn': 2, 'tc': 0x0e, 'cid': 0x28, 'iid': 0x00, 'snc': 0x01},
    'reg-enable':  {'chn': 2, 'tc': 0x21, 'cid': 0x01, 'iid': 0x00, 'snc': 0x01},
    'reg-disable': {'chn': 2, 'tc': 0x21, 'cid': 0x02, 'iid': 0x00, 'snc': 0x01},
}


def lo16(rqid):
    return rqid & 0xff


def hi16(rqid):
    return (rqid >> 8) & 0xff


def event_payload(rqid, tc, iid, seq):
    return bytes([tc, seq, lo16(rqid), hi16(rqid), iid])


def command(tc, cid, iid, chn, snc, payload):
    return bytes([tc, cid, iid, chn, snc, len(payload)]) + payload


def event_command(name, ev_tc, ev_seq, ev_iid):
    payload = event_payload(ev_tc, ev_tc, ev_iid, ev_seq)
    return command(**EVCMDS[name], payload=payload)


def run_command(data):
    fd = os.open(PATH_DEV_RQST, os.O_RDWR | os.O_SYNC)
    os.write(fd, data)

    os.lseek(fd, 0, os.SEEK_SET)
    length = os.read(fd, 1)[0]
    data = os.read(fd, length)

    os.close(fd)

    print(' '.join(['{:02x}'.format(x) for x in data]))


def main():
    cmd_name = sys.argv[1]

    if cmd_name == 'help':
        print(f'Usage:')
        print(f'  {sys.argv[0]} <command> [args...]')
        print(f'')
        print(f'Commands:')
        print(f'  help')
        print(f'    display this help message')
        print(f'')
        print(f'  command <tc> <cid> <iid> <channel> <snc> [payload...]')
        print(f'    basic command with optional payload')
        print(f'')

        for cmd in reversed(sorted(list(EVCMDS.keys()))):
            evsys, ty = cmd.split('-', 1)
            print(f'  {cmd} <ev_tc> <ev_seq> <ev_iid>')
            print(f'    {ty} event using {evsys.upper()} subsystem')
            print(f'')

        print(f'Arguments:')
        print(f'  <tc>:          command target category')
        print(f'  <cid>:         command ID')
        print(f'  <iid>:         command instance ID')
        print(f'  <channel>:     communication channel')
        print(f'  <snc>:         command-expects-response flag')
        print(f'  <ev_tc>:       event target category')
        print(f'  <ev_seq>:      event-is-sequenced flag')
        print(f'  <ev_iid>:      event instance ID')
        print(f'  [payload...]:  optional payload bytes, separated by whitespace')

    elif cmd_name == 'command':
        tc = int(sys.argv[2], 0)
        cid = int(sys.argv[3], 0)
        iid = int(sys.argv[4], 0)
        chn = int(sys.argv[5], 0)
        snc = int(sys.argv[6], 0)
        pld = [int(x, 0) for x in sys.argv[7:]]

        run_command(command(tc, cid, iid, chn, snc, bytes(pld)))

    else:
        ev_tc = int(sys.argv[2], 0)
        ev_seq = int(sys.argv[3], 0)
        ev_iid = int(sys.argv[4], 0)

        run_command(event_command(cmd_name, ev_tc, ev_seq, ev_iid))


if __name__ == '__main__':
    main()
