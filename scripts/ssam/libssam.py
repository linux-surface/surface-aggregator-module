from dataclasses import dataclass

import fcntl
import ctypes
import errno
import os


_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(dir, ty, nr, size):
    return (dir << _IOC_DIRSHIFT)  \
        | (ty << _IOC_TYPESHIFT)   \
        | (nr << _IOC_NRSHIFT)     \
        | (size << _IOC_SIZESHIFT)


def _IO(ty, nr):
    return _IOC(_IOC_NONE, ty, nr, 0)


def _IOR(ty, nr, size):
    return _IOC(_IOC_READ, ty, nr, size)


def _IOW(ty, nr, size):
    return _IOC(_IOC_WRITE, ty, nr, size)


def _IOWR(ty, nr, size):
    return _IOC(_IOC_WRITE | _IOC_READ, ty, nr, size)


class _RawRequestPayload(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('data', ctypes.c_uint64),
        ('length', ctypes.c_uint16),
        ('__pad', ctypes.c_uint8 * 6),
    ]


class _RawRequestResponse(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('data', ctypes.c_uint64),
        ('length', ctypes.c_uint16),
        ('__pad', ctypes.c_uint8 * 6),
    ]


class _RawRequest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_category', ctypes.c_uint8),
        ('target_id', ctypes.c_uint8),
        ('command_id', ctypes.c_uint8),
        ('instance_id', ctypes.c_uint8),
        ('flags', ctypes.c_uint16),
        ('status', ctypes.c_int16),
        ('payload', _RawRequestPayload),
        ('response', _RawRequestResponse),
    ]


class _RawNotifierDesc(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('priority', ctypes.c_int32),
        ('target_category', ctypes.c_uint8),
    ]


class _RawEventReg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_category', ctypes.c_uint8),
        ('target_id', ctypes.c_uint8),
        ('cid_enable', ctypes.c_uint8),
        ('cid_disable', ctypes.c_uint8),
    ]


class _RawEventId(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_category', ctypes.c_uint8),
        ('instance', ctypes.c_uint8),
    ]


class _RawEventDesc(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('reg', _RawEventReg),
        ('id', _RawEventId),
        ('flags', ctypes.c_uint8),
    ]


class _RawEventHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_category', ctypes.c_uint8),
        ('target_id', ctypes.c_uint8),
        ('command_id', ctypes.c_uint8),
        ('instance_id', ctypes.c_uint8),
        ('length', ctypes.c_uint16),
    ]


class Request:
    target_category: int
    target_id: int
    command_id: int
    instance_id: int
    flags: int
    payload: bytes
    response_cap: int

    def __init__(self, target_category, target_id, command_id, instance_id,
                 flags=0, payload=bytes(), response_cap=1024):
        self.target_category = target_category
        self.target_id = target_id
        self.command_id = command_id
        self.instance_id = instance_id
        self.flags = flags
        self.payload = payload
        self.response_cap = response_cap


@dataclass
class EventRegistry:
    target_category: int
    target_id: int
    cid_enable: int
    cid_disable: int


@dataclass
class EventId:
    target_category: int
    instance: int


@dataclass
class EventDescriptor:
    reg: EventRegistry
    id: EventId
    flags: int


class Event:
    target_category: int
    target_id: int
    command_id: int
    instance_id: int
    data: bytes

    def __init__(self, target_category, target_id, command_id, instance_id,
                 data=bytes()):
        self.target_category = target_category
        self.target_id = target_id
        self.command_id = command_id
        self.instance_id = instance_id
        self.data = data

    def __repr__(self):
        return f"Event {{ "                     \
            f"tc={self.target_category:02x}, "  \
            f"tid={self.target_id:02x}, "       \
            f"cid={self.command_id:02x}, "      \
            f"iid={self.instance_id:02x}, "     \
            f"data=[{', '.join('{:02x}'.format(x) for x in self.data)}] }}"

    def to_dict(self):
        return {
            "tc": self.target_category,
            "tid": self.target_id,
            "cid": self.command_id,
            "iid": self.instance_id,
            "data": list(self.data),
        }


REQUEST_HAS_RESPONSE = 1
REQUEST_UNSEQUENCED = 2


_PATH_SSAM_DBGDEV = '/dev/surface/aggregator'

_IOCTL_REQUEST = _IOWR(0xA5, 1, ctypes.sizeof(_RawRequest))
_IOCTL_NOTIF_REGISTER = _IOW(0xA5, 2, ctypes.sizeof(_RawNotifierDesc))
_IOCTL_NOTIF_UNREGISTER = _IOW(0xA5, 3, ctypes.sizeof(_RawNotifierDesc))
_IOCTL_EVENTS_ENABLE = _IOW(0xA5, 4, ctypes.sizeof(_RawEventDesc))
_IOCTL_EVENTS_DISABLE = _IOW(0xA5, 5, ctypes.sizeof(_RawEventDesc))


def _request(fd, rqst: Request):
    # set up basic request fields
    raw = _RawRequest()
    raw.target_category = rqst.target_category
    raw.target_id = rqst.target_id
    raw.command_id = rqst.command_id
    raw.instance_id = rqst.instance_id
    raw.flags = rqst.flags
    raw.status = -errno.ENXIO

    # set up payload
    if rqst.payload:
        pld_type = ctypes.c_uint8 * len(rqst.payload)
        pld_buf = pld_type(*rqst.payload)
        pld_ptr = ctypes.pointer(pld_buf)
        pld_ptr = ctypes.cast(pld_ptr, ctypes.c_void_p)

        raw.payload.data = pld_ptr.value
        raw.payload.length = len(rqst.payload)
    else:
        raw.payload.data = 0
        raw.payload.length = 0

    # set up response
    if rqst.response_cap > 0:
        rsp_cap = rqst.response_cap
        if rsp_cap > 0xffff:
            rsp_cap = 0xffff

        rsp_type = ctypes.c_uint8 * rsp_cap
        rsp_buf = rsp_type()
        rsp_ptr = ctypes.pointer(rsp_buf)
        rsp_ptr = ctypes.cast(rsp_ptr, ctypes.c_void_p)

        raw.response.data = rsp_ptr.value
        raw.response.length = rsp_cap
    else:
        raw.response.data = 0
        raw.response.length = 0

    # perform actual IOCTL
    buf = bytearray(raw)
    fcntl.ioctl(fd, _IOCTL_REQUEST, buf, True)
    raw = _RawRequest.from_buffer(buf)

    if raw.status:
        raise OSError(-raw.status, errno.errorcode.get(-raw.status))

    # convert response to bytes and return
    if raw.response.length > 0:
        return bytes(rsp_buf[:raw.response.length])
    else:
        return None


def _notifier_register(fd, target_category: int, priority: int):
    raw = _RawNotifierDesc()
    raw.priority = priority
    raw.target_category = target_category

    buf = bytes(raw)
    fcntl.ioctl(fd, _IOCTL_NOTIF_REGISTER, buf, False)


def _notifier_unregister(fd, target_category: int):
    raw = _RawNotifierDesc()
    raw.priority = 0
    raw.target_category = target_category

    buf = bytes(raw)
    fcntl.ioctl(fd, _IOCTL_NOTIF_UNREGISTER, buf, False)


def _event_enable(fd, desc: EventDescriptor):
    raw = _RawEventDesc()
    raw.reg.target_category = desc.reg.target_category
    raw.reg.target_id = desc.reg.target_id
    raw.reg.cid_enable = desc.reg.cid_enable
    raw.reg.cid_disable = desc.reg.cid_disable
    raw.id.target_category = desc.id.target_category
    raw.id.instance = desc.id.instance
    raw.flags = desc.flags

    buf = bytes(raw)
    fcntl.ioctl(fd, _IOCTL_EVENTS_ENABLE, buf, False)


def _event_disable(fd, desc: EventDescriptor):
    raw = _RawEventDesc()
    raw.reg.target_category = desc.reg.target_category
    raw.reg.target_id = desc.reg.target_id
    raw.reg.cid_enable = desc.reg.cid_enable
    raw.reg.cid_disable = desc.reg.cid_disable
    raw.id.target_category = desc.id.target_category
    raw.id.instance = desc.id.instance
    raw.flags = desc.flags

    buf = bytes(raw)
    fcntl.ioctl(fd, _IOCTL_EVENTS_DISABLE, buf, False)


def _event_read_blocking(fd):
    data = bytes()
    while len(data) < ctypes.sizeof(_RawEventHeader):
        data += os.read(fd, ctypes.sizeof(_RawEventHeader) - len(data))

    hdr = _RawEventHeader.from_buffer_copy(data)

    data = bytes()
    while len(data) < hdr.length:
        data += os.read(fd, hdr.length - len(data))

    return Event(hdr.target_category, hdr.target_id, hdr.command_id,
                 hdr.instance_id, data)


class Controller:
    def __init__(self):
        self.fd = None

    def open(self):
        self.fd = os.open(_PATH_SSAM_DBGDEV, os.O_RDWR)
        return self

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def request(self, request: Request):
        if self.fd is None:
            raise RuntimeError("controller is not open")

        return _request(self.fd, request)

    def notifier_register(self, target_category: int, priority: int = 0):
        if self.fd is None:
            raise RuntimeError("controller is not open")

        return _notifier_register(self.fd, target_category, priority)

    def notifier_unregister(self, target_category: int):
        if self.fd is None:
            raise RuntimeError("controller is not open")

        return _notifier_unregister(self.fd, target_category)

    def event_enable(self, desc: EventDescriptor):
        if self.fd is None:
            raise RuntimeError("controller is not open")

        return _event_enable(self.fd, desc)

    def event_disable(self, desc: EventDescriptor):
        if self.fd is None:
            raise RuntimeError("controller is not open")

        return _event_disable(self.fd, desc)

    def read_event(self):
        if self.fd is None:
            raise RuntimeError("controller is not open")

        return _event_read_blocking(self.fd)
