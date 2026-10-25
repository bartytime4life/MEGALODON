"""Discard desktop-session inheritable capabilities before starting HUD workers."""

import ctypes
import os
import sys


class _Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _Data(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def _capability_api():
    api = ctypes.CDLL(None, use_errno=True)
    for name in ("capget", "capset"):
        function = getattr(api, name)
        function.argtypes = [ctypes.POINTER(_Header), ctypes.POINTER(_Data)]
        function.restype = ctypes.c_int
    return api


def drop_inherited_capabilities() -> None:
    """Only remove inheritable bits; existing AI checks still validate all sets.

    Some desktop sessions pass CAP_WAKE_ALARM through the user service manager.
    It is unnecessary for the HUD and makes capability-free AI checks refuse.
    Call on the main thread before workers start: capabilities are per-thread.
    Root launches remain subject to the existing normal-user admission checks.
    """
    if sys.platform != "linux" or os.geteuid() == 0:
        return
    api = _capability_api()
    header = _Header(0x20080522, 0)  # Linux capability ABI v3, current thread.
    data = (_Data * 2)()

    def read() -> None:
        if api.capget(ctypes.byref(header), data) != 0:
            raise OSError(ctypes.get_errno(), "Cannot inspect HUD process capabilities")

    read()
    if not any(word.inheritable for word in data):
        return
    for word in data:
        word.inheritable = 0
    if api.capset(ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "Cannot discard inherited HUD capabilities")
    read()
    if any(word.inheritable for word in data):
        raise ValueError("HUD inherited capabilities were not cleared")
