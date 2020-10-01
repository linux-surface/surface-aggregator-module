#!/usr/bin/env python3
import json
import sys

import libssam
from libssam import Controller, Request


def dump_raw_data(data):
    print(json.dumps([x for x in data]))


class SurfaceLegacyKeyboard:
    def __init__(self, ctrl):
        self.ctrl = ctrl

    def get_device_descriptor(self, entry):
        flags = libssam.REQUEST_HAS_RESPONSE
        rqst = Request(0x08, 0x02, 0x00, 0x00, flags, bytes([entry]))
        return self.ctrl.request(rqst)

    def get_hid_feature_report(self, num):
        flags = libssam.REQUEST_HAS_RESPONSE
        rqst = Request(0x08, 0x02, 0x0b, 0x00, flags, bytes([num]))
        return self.ctrl.request(rqst)

    def set_capslock_led(self, state):
        state_byte = 0x01 if state else 0x00
        rqst = Request(0x08, 0x02, 0x01, 0x00, 0, bytes([state_byte]))
        self.ctrl.request(rqst)


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
        print(f'  legacy-get-descriptor <entry>')
        print(f'    get the HID device descriptor identified by <entry>')
        print(f'')
        print(f'    <entry>:  1  HID descriptor')
        print(f'              2  HID report descriptor')
        print(f'              3  device attributes')
        print(f'')
        print(f'  legacy-get-feature-report <num>')
        print(f'    get the HID feature report identified by <num>')
        print(f'')
        print(f'  legacy-set-capslock-led <state>')
        print(f'    set the capslock led state')

    elif cmd_name == 'legacy-get-descriptor':
        entry = int(sys.argv[2], 0)

        with Controller() as ctrl:
            dev = SurfaceLegacyKeyboard(ctrl)
            dump_raw_data(dev.get_device_descriptor(entry))

    elif cmd_name == 'legacy-get-feature-report':
        num = int(sys.argv[2], 0)

        with Controller() as ctrl:
            dev = SurfaceLegacyKeyboard(ctrl)
            dump_raw_data(dev.get_hid_feature_report(num))

    elif cmd_name == 'legacy-set-capslock-led':
        state = int(sys.argv[2], 0)

        with Controller() as ctrl:
            dev = SurfaceLegacyKeyboard(ctrl)
            dump_raw_data(dev.set_capslock_led(state))

    else:
        print(f'Invalid command: \'{cmd_name}\', try \'{sys.argv[0]} help\'')
        sys.exit(1)


if __name__ == '__main__':
    main()
