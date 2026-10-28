"""Secret storage, cross-platform. Kept under this name because several modules import it.

The real work is in the platform back ends (osdep): Windows DPAPI, macOS Keychain. `protect`
turns a secret into an opaque token stored in settings.json; `unprotect` turns it back.
"""
from . import osdep

protect = osdep.protect
unprotect = osdep.unprotect
