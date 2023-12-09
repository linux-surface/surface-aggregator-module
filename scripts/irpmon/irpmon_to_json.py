#!/usr/bin/env python3
from __future__ import print_function
import sys
import codecs
import json
import time
import gzip
from collections import namedtuple
from enum import Enum

TARGET_DRIVER = "\Driver\iaLPSS2_UART2_ADL"

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# global offset in cmdbytes
data_idx = 0

def data_push(delta):
    global data_idx
    data_idx = data_idx + delta

def data_timestamp(timestamps):
    global data_idx
    prev = timestamps[0][0]
    for ts, idx in timestamps:
        if idx > data_idx:
            return prev
        prev = ts
    return None

class FrameCtrl:
    def __init__(self, type, len, pad, seq):
        self.type = type
        self.len = len
        self.pad = pad
        self.seq = seq

    def __str__(self):
        return f"type: {hex(self.type)}, len: {hex(self.len)}, pad: {hex(self.pad)}, " + \
               f"seq: {hex(self.seq)}"

    def to_dict(self):
        return {
            "type": self.type,
            "len": self.len,
            "pad": self.pad,
            "seq": self.seq,
        }


class FrameCmd:
    def __init__(self, type, tc, out, inc, iid, rqid_lo, rqid_hi, cid):
        self.type = type
        self.tc = tc
        self.sid = inc
        self.tid = out
        self.iid = iid
        self.rqid_lo = rqid_lo
        self.rqid_hi = rqid_hi
        self.cid = cid

    def __str__(self):
        return f"type: {hex(self.type)}, tc: {hex(self.tc)}, tid: {hex(self.tid)}, " + \
               f"sid: {hex(self.sid)}, iid: {hex(self.iid)}, rqid_lo: {hex(self.rqid_lo)}, " + \
               f"rqid_hi: {hex(self.rqid_hi)}, cid: {hex(self.cid)}"

    def to_dict(self):
        return {
            "type": self.type,
            "tc": self.tc,
            "sid": self.sid,
            "tid": self.tid,
            "iid": self.iid,
            "rqid_lo": self.rqid_lo,
            "rqid_hi": self.rqid_hi,
            "cid": self.cid,
        }


def drop_until_syn(data):
    for i in range(1, len(data)):
        if data[i] == 0xaa and data[i+1] == 0x55:
            eprint("data dropped: " + ' '.join(map(hex, data[:i])))
            data_push(i+2)
            return data[i+2:]


def parse_syn(data):
    if data[0:2] != bytes([0xaa, 0x55]):
        eprint("warning: expected SYN, skipping data until next SYN")
        drop_until_syn(data)

    data_push(2)
    return data[2:]


def parse_ter(data):
    if data[0:2] != bytes([0xff, 0xff]):
        eprint("warning: expected TER, skipping data until next SYN")
        drop_until_syn(data)

    data_push(2)
    return data[2:]


def skip_checksum(data):
    data_push(2)
    return data[2:]


def parse_frame_ctrl(data):
    ty = data[0]
    len = data[1]
    pad = data[2]
    seq = data[3]

    data_push(4)
    return data[4:], FrameCtrl(ty, len, pad, seq)


def parse_frame_cmd(data):
    ty = data[0]
    tc = data[1]
    out = data[2]
    inc = data[3]
    iid = data[4]
    rqid_lo = data[5]
    rqid_hi = data[6]
    cid = data[7]

    data_push(8)
    return data[8:], FrameCmd(ty, tc, out, inc, iid, rqid_lo, rqid_hi, cid)


def parse_commands(data, timestamps):
    records = []

    while data:
        data = parse_syn(data)
        data, ctrl = parse_frame_ctrl(data)
        data = skip_checksum(data)

        if ctrl.type == 0x00 or ctrl.type == 0x80:
            data, cmd = parse_frame_cmd(data)

            curtime = data_timestamp(timestamps)

            payload_len = ctrl.len - 8
            data_push(payload_len)
            data, pld = data[payload_len:], data[0:payload_len]

            data = skip_checksum(data)

            record = {"ctrl": ctrl.to_dict(), "cmd": cmd.to_dict(), "payload": list(pld), "time": curtime}
            records.append(record)

        elif ctrl.type == 0x40:
            data = parse_ter(data)
            records.append({"ctrl": ctrl.to_dict()})
        elif ctrl.type == 0x04:
            data = parse_ter(data)
            records.append({"ctrl": ctrl.to_dict()})

    return records

def process_records(records):
    all_data = bytearray([])
    timestamps = []

    # for r in records:
        # print(r)

    for record in records:
        if not record.function in (Function.Read, Function.Write):
            continue
        # if not record.status in (Status.STATUS_SUCCESS, Status.STATUS_PENDING):
            # continue
        # Ok, data is good, add it.
        all_data.extend(record.data)
        timestamps.append((record.time, len(all_data)))

    timestamps.append((None, len(all_data)))

    # print(list(all_data))
    return bytes(all_data), timestamps


# Helper to hold the relevant fields from the log records.
Irp = namedtuple("Irp", [
    "id",
    "function",
    "time",
    "status",
    "address",
    "data",
])

Function = Enum('Function', [
    'Read',
    'Write',
    'PnP',
    'Create',
    'Cleanup',
    'Close',
    'DeviceControl',
    'SystemControl',
    'Power',
    ])


Status = Enum('Status', [
    'STATUS_SUCCESS',
    'STATUS_NOT_SUPPORTED',
    'STATUS_PENDING',
    'STATUS_CANCELLED',
    'STATUS_TIMEOUT'])


"""
    Parse the log file, returning a list of records that pertain to the 
    target driver.
"""
def parse_log_file(file):
    major_function = 'NONE'
    irp_id = None
    irp_address = None
    curtime = None
    status = None
    address = None

    data = False
    lines = []
    discard = False

    records = []

    for line_nr, line in enumerate(file):
        if line.startswith("ID ="):
            irp_id = int(line.split('=', 1)[1].strip())
        elif line.startswith("Major function ="):
            function = Function[line.split('=', 1)[1].strip()]
        elif line.startswith("IRP address ="):
            irp_address = int(line.split('=', 1)[1].strip(), 0)
        elif line.startswith("Driver name = "):
            discard = line.split('=', 1)[1].strip() != TARGET_DRIVER
        elif line.startswith("Time = "):
            curtime = line.split('=', 1)[1].strip()
            # curtime = time.strptime(curtime, '%m/%d/%Y %I:%M:%S %p')
        elif line.startswith("IOSB.Status constant"):
            status_constant = Status[line.split('=', 1)[1].strip()]
        elif line.startswith("Data (Hexer)"):
            data = True
        elif data and line.startswith("  ") and line.strip():
            lines.append(line.strip())
        elif data:
            bytedata = []
            for l in lines:
                strdata = l.split("\t")[1]
                bytedata.extend([int(x, 16) for x in strdata.split()])

            if not discard:
                record = Irp(
                    id = irp_id,
                    function = function,
                    time = curtime,
                    status = status_constant,
                    address = irp_address,
                    data = bytedata)
                records.append(record)


            data = False
            discard = False
            lines = []

    return records

"""
    Parse the json file, returning a list of records that pertain to the 
    target driver.
"""
def parse_json_file(path):
    opener = gzip.open if path.endswith("gz") else open

    # This isn't compliant json, the 'stack' parameter is formatting is broken.
    with opener(path, "rt") as f:
        file_text = f.read()

    # Patch the stack parameters
    """
    <...> denotes snip of repeating patterns
        "Stack" : [{"Address" : 0x00007FFEBD5AF874, ), ,  <...>  {"Address" : 0x00007FFEBD56AA65, ), ]},
    """
    fixed_string = ""
    # Check for the bad syntax first, future proofing if this gets fixed.
    if ", ), ," in file_text:
        # So we strip from '"Stack" : [' to the first `]`
        # We can use string indexing and avoid regular expressions for speed.
        current_index = 0
        left_pattern = ', "Stack" : ['
        right_pattern = ']'
        while current_index != -1:
            # Find until the next broken section
            left_index = file_text.find(left_pattern, current_index)
            fixed_string += file_text[current_index:left_index]
            if left_index == -1:
                # No more tokens, add the closing bracket.
                fixed_string += file_text[-1]
                break;
            # Skip over the broken part.
            right_index = file_text.find(right_pattern, left_index)
            current_index = right_index + 1
    else:
        fixed_string = file_text

    # Lets also add some newlines, in case we need to open the file.
    fixed_string = fixed_string.replace('},{"ID"', '},\n{"ID"');

    
    #with open("/tmp/fixed.json", "w") as f:
    #    f.write(fixed_string)

    irp_entries = json.loads(fixed_string)

    records = []
    # Now we have good and clean data.
    for entry in irp_entries:
        if entry.get("Driver name") != TARGET_DRIVER:
            continue

        if entry.get("Type") != "IRP":
            # "DriverDetected"
            continue

        data = entry.get("Parsers", {}).get("Hexer", {}).get("Data0", '')
        bytedata = [a for a in codecs.decode(data, 'hex_codec')]

        irp_id = int(entry.get("ID"))
        function = Function[entry.get("Major function")]
        curtime = entry.get("Time")
        status_constant = Status[entry.get("IOSB.Status constant")]
        irp_address =  int(entry.get("IRP address"), 0)
        record = Irp(
            id = irp_id,
            function = function,
            time = curtime,
            status = status_constant,
            address = irp_address,
            data = bytedata)
        records.append(record)
    return records

def main(in_file):
    if in_file.endswith("json") or in_file.endswith("json.gz"):
        records = parse_json_file(in_file)
    else:
        opener = gzip.open if in_file.endswith("gz") else open
        with opener(in_file, "rb") as f:
            records = parse_log_file(codecs.iterdecode(f, encoding='utf-8', errors='ignore'))

    data, timestamps = process_records(records)

    json_string = json.dumps(parse_commands(data, timestamps))
    # This is safe as bytes are represented with integers.
    json_string = json_string.replace("}, {", "},\n{")
    print(json_string)


if __name__ == '__main__':
    main(sys.argv[1])
