"""Windows DPAPI: encrypt secrets so only this Windows user on this PC can read them."""
import base64
import ctypes
from ctypes import wintypes


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32
_ENTROPY = b"OrbiControl/v1"


def _blob(data: bytes) -> _Blob:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _take(blob: _Blob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        _kernel32.LocalFree(blob.pbData)


def protect(text: str) -> str:
    src, ent, out = _blob(text.encode("utf-8")), _blob(_ENTROPY), _Blob()
    if not _crypt32.CryptProtectData(ctypes.byref(src), "OrbiControl", ctypes.byref(ent), None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return base64.b64encode(_take(out)).decode("ascii")


def unprotect(token: str) -> str:
    src, ent, out = _blob(base64.b64decode(token)), _blob(_ENTROPY), _Blob()
    if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return _take(out).decode("utf-8")
