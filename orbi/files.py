"""Whole-PC file access for the web app (behind the PIN; off until turned on in More → Files).

Every filesystem call runs with a timeout: this PC's optical drives can hang any drive or volume
query forever, and a hung call must not take a request (or the UI) down with it.
"""
import ctypes
import os
import shutil
import string
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

TIMEOUT = 8  # seconds
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="files")


class FileError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def run(fn, *args, timeout=TIMEOUT):
    try:
        return _pool.submit(fn, *args).result(timeout=timeout)
    except FutureTimeout:
        raise FileError(504, "That drive isn't responding (an optical drive or sleeping disk?)")
    except FileNotFoundError:
        raise FileError(404, "Not found")
    except PermissionError:
        raise FileError(403, "Windows denied access to that")
    except FileExistsError:
        raise FileError(409, "Something with that name already exists")
    except OSError as e:
        raise FileError(400, e.strerror or str(e))


def resolve(path: str) -> str:
    """Absolute local path; network (UNC) paths are refused so the PC never reaches out to other hosts."""
    if not path or "\0" in path:
        raise FileError(400, "Path required")
    path = path.replace("/", "\\")
    if path.startswith("\\\\"):
        raise FileError(400, "Network paths aren't supported")
    if len(path) == 2 and path[1] == ":":
        path += "\\"
    if not os.path.isabs(path):
        raise FileError(400, "Use a full path like C:\\Users")
    return os.path.normpath(path)


def drives() -> list[dict]:
    # GetLogicalDrives is a bitmask read that never touches the drives themselves, so it can't hang.
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    return [{"name": f"{c}:", "path": f"{c}:\\", "dir": True} for i, c in enumerate(string.ascii_uppercase) if mask >> i & 1]


def _listdir(path):
    out = []
    with os.scandir(path) as it:
        for e in it:
            try:
                is_dir = e.is_dir()
                st = e.stat()
                out.append({"name": e.name, "path": e.path, "dir": is_dir, "size": None if is_dir else st.st_size, "mtime": st.st_mtime})
            except OSError:
                out.append({"name": e.name, "path": e.path, "dir": False, "size": None, "mtime": None, "error": True})
    out.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return out


def listdir(path: str) -> dict:
    path = resolve(path)
    entries = run(_listdir, path)
    parent = os.path.dirname(path)
    return {"path": path, "parent": parent if parent != path else "", "entries": entries}


def _file_info(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return os.path.getsize(path)


def file_size(path: str) -> int:
    return run(_file_info, path)


def mkdir(parent: str, name: str) -> str:
    target = os.path.join(resolve(parent), check_name(name))
    run(os.mkdir, target)
    return target


def rename(path: str, new_name: str) -> str:
    path = resolve(path)
    target = os.path.join(os.path.dirname(path), check_name(new_name))
    if run(os.path.lexists, target):
        raise FileError(409, "Something with that name already exists")
    run(os.rename, path, target)
    return target


def _delete(path, recursive):
    if os.path.isdir(path) and not os.path.islink(path):
        if recursive:
            shutil.rmtree(path)
        else:
            os.rmdir(path)
    else:
        os.remove(path)


def delete(path: str, recursive: bool = False):
    path = resolve(path)
    if os.path.dirname(path) == path:
        raise FileError(400, "Drives can't be deleted")
    try:
        run(_delete, path, recursive, timeout=300 if recursive else TIMEOUT)
    except FileError as e:
        if e.status == 400 and not recursive and run(os.path.isdir, path):
            raise FileError(409, "Folder isn't empty")
        raise


def check_name(name: str) -> str:
    name = (name or "").strip()
    if not name or name in (".", "..") or any(c in name for c in '\\/:*?"<>|\0'):
        raise FileError(400, "That isn't a valid file or folder name")
    return name
