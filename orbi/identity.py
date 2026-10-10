"""Spots a device passing itself off as something else.

The router identifies every device by itself (brand and category, from the device's network fingerprint) as well
as reporting the name the device gives itself. A laptop renamed "Echo-Dot" to slip into an unrestricted profile
still shows up to the router as an Apple laptop. Only names the device chose are checked: a name someone typed
into the Orbi app says nothing about the device.

This can't catch everything: a jailbroken Echo really is Amazon hardware, so the router still says Amazon.
"""
import re

# A word in a device's own name -> (the brand it implies, the kind of device it implies)
CLAIMS = [
    (r"\becho\b|alexa|kindle|fire.?tv|fire.?stick", "Amazon", "smart speaker or streaming"),
    (r"homepod|apple.?tv|airport", "Apple", "speaker or streaming"),
    (r"iphone|ipad|macbook|imac|mac.?mini", "Apple", None),
    (r"sonos", "Sonos", "speaker"),
    (r"playstation|\bps[345]\b", "Sony", "game console"),
    (r"xbox", "Microsoft", "game console"),
    (r"chromecast|google.?home|nest.?(hub|mini|audio)", "Google", "smart speaker or streaming"),
    (r"\bkasa\b|\bhs10[03-5]\b|\bkp\d{3}\b", "TP-Link", "smart plug"),
]
# Categories the router gives computers and phones: what a disguised laptop really is.
GENERAL_PURPOSE = {"LAPTOP", "DESKTOP", "COMPUTER", "MOBILE", "TABLET", "PC"}
BRAND_ALIASES = {"amazon": "amazon", "apple": "apple", "sonos": "sonos", "sony": "sony", "microsoft": "microsoft",
                 "google": "google", "tp-link": "tp-link", "tplink": "tp-link", "kasa": "tp-link"}


def _brand(b: str) -> str:
    b = (b or "").strip().lower()
    return next((v for k, v in BRAND_ALIASES.items() if b.startswith(k)), b)


def mismatch(name: str, brand: str, category: str, name_user_set: bool = False) -> str | None:
    """Why `name` doesn't fit what the router identified the device as, or None."""
    if name_user_set or not name:
        return None
    for pattern, claimed, kind in CLAIMS:
        if not re.search(pattern, name, re.I):
            continue
        if brand and _brand(brand) != _brand(claimed):
            return f"it calls itself \"{name}\", which sounds like {claimed}, but the router identifies it as made by {brand}"
        if kind and category in GENERAL_PURPOSE:
            return (f"it calls itself \"{name}\", which sounds like a {kind}, but the router identifies it as a "
                    f"{category.lower().replace('_', ' ')}")
        return None
    return None
