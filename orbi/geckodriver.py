"""The geckodriver that drives the headless Firefox, pinned to one version and checked by hash.

Without this, Selenium downloads whatever geckodriver it likes from GitHub on first use, outside the
hash-pinned dependencies. Here the release archive and the program inside it must match the hashes in
osdep.GECKODRIVER (one pin per OS: a win64 .zip, a macos-aarch64 .tar.gz) before the app will run it,
and they are checked again every time it starts.

To move to a newer geckodriver: download each OS's release archive, check it against Mozilla's
published signature, and update VERSION and both hashes in osdep/windows.py and osdep/macos.py.
"""
import hashlib
import io
import logging
import os
import tarfile
import urllib.request
import zipfile

from . import config, osdep

log = logging.getLogger("orbi.geckodriver")

SPEC = osdep.GECKODRIVER
VERSION = SPEC["version"]
MAX_ZIP = 20_000_000


class GeckodriverError(Exception):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract(data: bytes) -> bytes:
    """The geckodriver binary out of the downloaded archive (zip on Windows, tar.gz on macOS)."""
    if SPEC["archive"] == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.read(SPEC["member"])
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        f = t.extractfile(SPEC["member"])
        if f is None:
            raise GeckodriverError(f"{SPEC['member']} not found in the {VERSION} download")
        return f.read()


def path():
    """Path to the verified geckodriver, downloading and checking it the first time."""
    exe = config.DATA_DIR / "geckodriver" / VERSION / SPEC["exe_name"]
    if exe.is_file() and _sha256(exe.read_bytes()) == SPEC["binary_sha256"]:
        return exe
    log.info("downloading geckodriver %s", VERSION)
    req = urllib.request.Request(SPEC["url"], headers={"User-Agent": "OrbiControl"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_ZIP + 1)
    if len(data) > MAX_ZIP or _sha256(data) != SPEC["archive_sha256"]:
        raise GeckodriverError(f"The geckodriver {VERSION} download doesn't match its pinned hash, so it wasn't used")
    prog = _extract(data)
    if _sha256(prog) != SPEC["binary_sha256"]:
        raise GeckodriverError(f"geckodriver inside the {VERSION} download doesn't match its pinned hash")
    exe.parent.mkdir(parents=True, exist_ok=True)
    tmp = exe.with_suffix(".tmp")
    tmp.write_bytes(prog)
    tmp.replace(exe)
    if not osdep.IS_WINDOWS:
        os.chmod(exe, 0o755)  # the tarball bit may not survive; Selenium must be able to exec it
    return exe
