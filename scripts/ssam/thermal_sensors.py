#!/usr/bin/env python3
import struct

import libssam
from libssam import Controller, Request


def get_sensors(ctrl):
    rqst = Request(0x03, 0x01, 0x04, 0x00, libssam.REQUEST_HAS_RESPONSE)
    data = ctrl.request(rqst)

    sensor_bits = struct.unpack('H', data)[0]

    return [i + 1 for i in range(16) if (sensor_bits & (1 << i))]


def get_name(ctrl, iid):
    rqst = Request(0x03, 0x01, 0x0e, iid, libssam.REQUEST_HAS_RESPONSE)
    data = ctrl.request(rqst)
    name = data[3:].decode('utf-8').strip("\x00")

    return name


def get_temperature(ctrl, iid):
    rqst = Request(0x03, 0x01, 0x01, iid, libssam.REQUEST_HAS_RESPONSE)
    data = ctrl.request(rqst)

    temp = struct.unpack('H', data)[0]
    temp = (temp - 2731) / 10

    return temp

def main():
    with Controller() as ctrl:
        sensors = get_sensors(ctrl)

        print(f"IID  NAME    TEMPERATURE")
        for iid in sensors:
            name = get_name(ctrl, iid)
            temp = get_temperature(ctrl, iid)

            print(f"{iid:3} {name: >7} {temp:5.1f}°C")


if __name__ == '__main__':
    main()
