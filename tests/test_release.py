import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("release", Path(__file__).resolve().parent.parent / "scripts" / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

NOTES = """Orbi Control 1.2.0

New
- A thing.
  - A detail.

After updating, sign in again."""


def test_changelog_entry():
    assert release.changelog_entry("1.2.0", "2026-11-01", NOTES) == (
        "## 1.2.0 (2026-11-01)\n\n### New\n- A thing.\n  - A detail.\n\nAfter updating, sign in again.\n")


def test_newest_version_goes_on_top():
    text = release.add_to_changelog("", release.changelog_entry("1.1.0", "2026-10-01", "- Old."))
    text = release.add_to_changelog(text, release.changelog_entry("1.2.0", "2026-11-01", "- New."))
    assert text.startswith(release.CHANGELOG_HEADER)
    assert text.index("## 1.2.0") < text.index("## 1.1.0")
