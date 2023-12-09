#!/usr/bin/env python3
from __future__ import print_function
import sys
import codecs
import json
import time
import gzip
from collections import namedtuple
from enum import Enum


# Name of the driver of interest, any log records pertaining to others are
# ignored.
TARGET_DRIVER = "\Driver\iaLPSS2_UART2_ADL"

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

"""
    Helper function to format integers or iterables as hexadecimal.
"""
def hfmt(b):
    if type(b) is int:
        return f"{b:0>2x}"
    return " ".join(f"{x:0>2x}" for x in b)

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

# Helper type to keep track of the outer index (into the Irp records) and the 
# inner index (the byte offset in this irp record).
RecordIndex = namedtuple("RecordIndex", ["outer", "inner"])
RecordIndex.advance_outer = lambda self: RecordIndex(outer=self.outer+1, inner=0)


"""
Notes:

    The problem is that it is possible for writes to be interleaved with
    extended read commands.

ID = 512
Type = IRPComp
Major function = Read
IRP address = 0xFFFF9A071E5BB670
IOSB.Status constant = STATUS_SUCCESS
Data size = 48
  00:	aa 55 80 1d 00 48 06 91 80 02 00 01 01 4e 00 53
  10:	01 9a 5e 02 00 42 5d 01 00 4e 00 f7 21 60 ea 00
  20:	00 3c 73 00 00 83 86 aa 55 40 00 00 26 f8 ae ff

ID = 513
Type = IRP
Major function = Write
IRP address = 0xFFFF9A071E7B3670
IOSB.Status constant = STATUS_SUCCESS
Data size = 10
  0:	aa 55 40 00 00 48 90 23 ff ff

ID = 514
Type = IRPComp
Major function = Write
IRP address = 0xFFFF9A071E7B3670
IOSB.Status constant = STATUS_SUCCESS


ID = 515
Type = IRP
Major function = Read
Minor function = Normal
IRP address = 0xFFFF9A071E5BB9A0
IOSB.Status constant = STATUS_SUCCESS

ID = 516
Type = IRPComp
Major function = Read
IRP address = 0xFFFF9A071E5BB9A0
IOSB.Status constant = STATUS_SUCCESS
Data size = 48
  00:	ff aa 55 80 46 00 49 18 2f 80 0c 00 01 00 4f 00
  10:	0e ff ff 04 00 01 03 00 02 02 00 03 01 00 03 09
  20:	00 01 06 00 01 ff ff ff 00 00 00 00 00 00 00 00

Note how ID 516, is a continuation of ID 512.
A problem is that 513 and 514 are a write that's in between the reads.
"""

"""
    Parser to convert irp records into the SSAM commands.
"""
class Parser:
    def __init__(self, records):
        # Input IRP records
        self.records = records
        # Index of current record entry.
        self.index = RecordIndex(0, 0)

        # Initialise the cursor, by jumping over the records to be ignored
        self.advance(0)

        # Parsed communication.
        self.comm = []

    """
        Retrieve the parsed communication.
    """
    def communication(self):
        return self.comm

    """
        Returns a new record index offset away from the current index.
    """
    def advanced_index(self, offset):
        inner = self.index.inner

        # print(f"Advancing from {self.index} to offset {offset}")
        for outer in range(self.index.outer, len(self.records)):
            this_record = self.records[outer]

            # Check if this is to be ignored.
            if not this_record.function in (Function.Read, Function.Write):
                continue
            #if this_record.status in (Status.STATUS_TIMEOUT, ):
            #    continue

            if (inner + offset) < len(this_record.data):
                # This offset is in this outer index.
                return RecordIndex(outer, inner + offset)
            else:
                # Subtract what bytes remain in this record.
                offset -= (len(this_record.data) - inner)

            # We're advancing the outer index, so inner becomes zero.
            inner = 0

        # If we don't find it, we reached the end, return a None
        return None

    """
        Returns data from the current cursor position onwards, defaults to
        returning a single byte, always returns a byte array object, even for
        length of one.
    """
    def data(self, offset, length=1):
        index = self.advanced_index(offset)

        buffer = bytearray([])
        while length:
            from_this = self.records[index.outer].data[index.inner:index.inner+length]
            length -= len(from_this)
            buffer.extend(from_this)
            index = index.advance_outer()
        return buffer

    """
        Advances the index by the desired offset.
    """
    def advance(self, offset):
        self.index = self.advanced_index(offset)
        # print(f"New cursor: {self.index}")

    """
        Returns true if the current index is None, indicating the cursor has
        advanced beyond the records.
    """
    def is_exhausted(self):
        return self.index is None

    """
        Returns the current record, or if the parser is exhausted the last one.
    """
    def current_record(self):
        if self.is_exhausted():
            return self.records[-1]
        return self.records[self.index.outer]

    """
        Process all records available and store the parsed results.
    """
    def parse(self):
        while self.index:
            self.parse_syn()
            ctrl = self.parse_frame_ctrl()
            self.skip_checksum()

            if ctrl.type == 0x00 or ctrl.type == 0x80:
                frame_cmd = self.parse_frame_cmd()

                payload_len = ctrl.len - 8

                payload = self.data(0, length=payload_len)
                self.advance(payload_len)

                self.skip_checksum()

                curtime = self.current_record().time
                record = {"ctrl": ctrl.to_dict(), "cmd": frame_cmd.to_dict(), "payload": list(payload), "time": curtime}
                self.comm.append(record)

            elif ctrl.type == 0x40:
                data = self.parse_ter()
                self.comm.append({"ctrl": ctrl.to_dict()})
            elif ctrl.type == 0x04:
                data = self.parse_ter()
                self.comm.append({"ctrl": ctrl.to_dict()})


    def drop_until_syn(self):
        raise NotImplemented("todo")
        for i in range(1, len(data)):
            if data[i] == 0xaa and data[i+1] == 0x55:
                eprint("data dropped: " + ' '.join(map(hex, data[:i])))
                data_push(i+2)
                return data[i+2:]


    def parse_syn(self):
        expected_syn = self.data(0, length=2)
        if expected_syn[0] != 0xaa or expected_syn[1] != 0x55:
            eprint(f"Warning: expected SYN, skipping data until next SYN, instead got {hfmt(expected_syn)}")
            eprint(f"Current index: {self.index}")
            eprint(f"Current record: {self.current_record()}")
            self.drop_until_syn()
        self.advance(2)


    def parse_ter(self):
        expected_ter = self.data(0, length=2)
        if expected_ter[0] != 0xff or expected_ter[1] != 0xff:
            eprint(f"Warning: Expected full terminate, instead got {hfmt(expected_ter)}")
            eprint(f"Current index: {self.index}")
            eprint(f"Current record: {self.current_record()}")

            if expected_ter[0] == 0xff and expected_ter[1] == 0xaa:
                eprint("Got half TER, with 0xAA after terminate, removing 0xFF")
                self.advance(1)
                return
            self.drop_until_syn()
        self.advance(2)


    def skip_checksum(self):
        checksum = self.data(0, length=2)
        self.advance(2)

    def parse_frame_ctrl(self):
        b = self.data(0, 4)
        (ty, len, pad, seq) = b
        self.advance(4)
        return FrameCtrl(ty, len, pad, seq)

    def parse_frame_cmd(self):
        data = self.data(0, length=8)
        ty = data[0]
        tc = data[1]
        out = data[2]
        inc = data[3]
        iid = data[4]
        rqid_lo = data[5]
        rqid_hi = data[6]
        cid = data[7]
        self.advance(8)

        return FrameCmd(ty, tc, out, inc, iid, rqid_lo, rqid_hi, cid)



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
        elif line.startswith("Type = "):
            discard = discard or line.split('=', 1)[1].strip() == "DriverDetected"
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

    # This isn't compliant json, the 'stack' parameter's formatting is broken.
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

        if entry.get("Type") == "DriverDetected":
            # "DriverDetected", "IRPComp"
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

    p = Parser(records)
    p.parse()
    # p.index = RecordIndex(8, 39)
    # print(hfmt(p.data(0, 20)))
    # p.advance(8)
    # print(hfmt(p.data(0, 20)))
    # p.advance(3)
    # print(hfmt(p.data(0, 20)))

    parsed_result = p.communication()

    json_string = json.dumps(parsed_result)
    # This is safe as bytes are represented with integers.
    json_string = json_string.replace("}, {", "},\n{")
    print(json_string)


if __name__ == '__main__':
    main(sys.argv[1])
