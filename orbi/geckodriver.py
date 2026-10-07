"""The geckodriver that drives the headless Firefox, pinned to one version and checked by hash.

Without this, Selenium downloads whatever geckodriver it likes from GitHub on first use, outside the
hash-pinned dependencies. Here the release zip and the program inside it must match the hashes below
before the app will run it, and they are checked again every time it starts.

To move to a newer geckodriver: download the release zip, check it against Mozilla's published signature,
and update VERSION and both hashes.
"""
import hashlib
import io
import logging
import urllib.request
import zipfile

from . import config

log = logging.getLogger("orbi.geckodriver")

VERSION = "0.37.1"
URL = f"https://github.com/mozilla/geckodriver/releases/download/v{VERSION}/geckodriver-v{VERSION}-win64.zip"
ZIP_SHA256 = "dfed9315abe8d2fbc1b6161a2ee8002452e79cf05ee92fdc653a4e26bc35edd8"
EXE_SHA256 = "e95b4eac7960ffcd5acbfd92bb7d49d48f99c1d01a20ddd297fef8c80821020d"
MAX_ZIP = 20_000_000


class GeckodriverError(Exception):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path():
    """Path to the verified geckodriver.exe, downloading and checking it the first time."""
    exe = config.DATA_DIR / "geckodriver" / VERSION / "geckodriver.exe"
    if exe.is_file() and _sha256(exe.read_bytes()) == EXE_SHA256:
        return exe
    log.info("downloading geckodriver %s", VERSION)
    req = urllib.request.Request(URL, headers={"User-Agent": "OrbiControl"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_ZIP + 1)
    if len(data) > MAX_ZIP or _sha256(data) != ZIP_SHA256:
        raise GeckodriverError(f"The geckodriver {VERSION} download doesn't match its pinned hash, so it wasn't used")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        prog = z.read("geckodriver.exe")
    if _sha256(prog) != EXE_SHA256:
        raise GeckodriverError(f"geckodriver.exe inside the {VERSION} download doesn't match its pinned hash")
    exe.parent.mkdir(parents=True, exist_ok=True)
    tmp = exe.with_suffix(".tmp")
    tmp.write_bytes(prog)
    tmp.replace(exe)
    return exe
