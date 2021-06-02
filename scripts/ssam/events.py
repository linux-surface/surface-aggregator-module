#!/usr/bin/env python3
import libssam
from libssam import Controller

import json
import sys


def print_help_and_exit():
    print(f'Usage:')
    print(f'  {sys.argv[0]} <command> [args...]')
    print(f'')
    print(f'Commands:')
    print(f'  help')
    print(f'    display this help message')
    print(f'')
    print(f'  listen <xx>[,<xx>][,...]')
    print(f'    listen to the specified target categories')
    print(f'')
    print(f'  enable <reg.tc> <reg.tid> <reg.cid_en> <reg.cid_dis> <tid> <iid> <flags>')
    print(f'    enable the specified event')
    print(f'')
    print(f'  disable <reg.tc> <reg.tid> <reg.cid_en> <reg.cid_dis> <tid> <iid> <flags>')
    print(f'    disable the specified event')
    print(f'')
    sys.exit(0)


def cmd_listen(as_json=False):
    if len(sys.argv) != 3:
        print("Error: Invalid number of parameters")
        sys.exit(0)

    categories = sys.argv[2].split(',')
    categories = [int(x, base=16) for x in categories]

    with Controller() as ctrl:
        for x in categories:
            ctrl.notifier_register(x)

        while True:
            if as_json:
                print(json.dumps(ctrl.read_event().to_dict()))
            else:
                print(ctrl.read_event())


def parse_event_descriptor(fields):
    fields = [int(x, 16) for x in fields]

    reg = libssam.EventRegistry(fields[0], fields[1], fields[2], fields[3])
    eid = libssam.EventId(fields[4], fields[5])
    evdesc = libssam.EventDescriptor(reg, eid, fields[6])

    return evdesc


def cmd_enable():
    if len(sys.argv) != 9:
        print("Error: Invalid number of parameters")
        sys.exit(0)

    evdesc = parse_event_descriptor(sys.argv[2:9])

    with Controller() as ctrl:
        ctrl.event_enable(evdesc)


def cmd_disable():
    if len(sys.argv) != 9:
        print("Error: Invalid number of parameters")
        sys.exit(0)

    evdesc = parse_event_descriptor(sys.argv[2:9])

    with Controller() as ctrl:
        ctrl.event_disable(evdesc)


def main():
    if len(sys.argv) < 2:
        print_help_and_exit()

    cmd_name = sys.argv[1]

    if cmd_name == 'help':
        print_help_and_exit()
    elif cmd_name == 'listen':
        cmd_listen()
    elif cmd_name == 'enable':
        cmd_enable()
    elif cmd_name == 'disable':
        cmd_disable()
    else:
        print("Error: Invalid command")
        sys.exit(0)


if __name__ == '__main__':
    main()
