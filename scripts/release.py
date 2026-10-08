"""Tags and signs a release so installed copies will accept it as an update.

    .venv\\Scripts\\python scripts\\release.py 1.2.0 "What changed, written for users"
    git push origin main --tags

Run it on the PC that holds the release key (%LOCALAPPDATA%\\OrbiControl\\release-signing-key,
DPAPI-encrypted for that Windows user). It checks that the work tree is clean and VERSION matches,
adds the notes to CHANGELOG.md (committed as "Changelog for X.Y.Z"), hashes every file in HEAD exactly as
GitHub's source zip will contain it, signs that list, and creates the annotated tag vX.Y.Z with the notes
plus an Orbi-Signature line. Nothing is pushed.

    .venv\\Scripts\\python scripts\\release.py --verify v1.2.0    re-checks an existing tag's signature
"""
import base64
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orbi import config, dpapi, ed25519, updater  # noqa: E402

KEY_FILE = config.DATA_DIR / "release-signing-key"
CHANGELOG = ROOT / "CHANGELOG.md"
CHANGELOG_HEADER = ("# Changelog\n\nWhat changed in each version, newest first. The same notes appear in the app under "
                    "More → Updates.\n")


def changelog_entry(version: str, date: str, notes: str) -> str:
    """Release notes as a CHANGELOG.md section. Short lines that aren't bullets become sub-headings."""
    lines = notes.strip().splitlines()
    if lines and lines[0].strip() == f"Orbi Control {version}":
        lines = lines[1:]
    while lines and not lines[0].strip():
        lines = lines[1:]
    out = [f"## {version} ({date})", ""]
    for line in lines:
        text = line.rstrip()
        if text and not text.lstrip().startswith("-") and len(text) < 60 and not text.endswith((".", ")", ":")):
            out.append(f"### {text}")
        else:
            out.append(text)
    return "\n".join(out).strip() + "\n"


def add_to_changelog(text: str, entry: str) -> str:
    """Puts `entry` above the newest version already in the changelog."""
    text = text or CHANGELOG_HEADER
    i = text.find("\n## ")
    if i == -1:
        return text.rstrip("\n") + "\n\n" + entry
    return text[:i + 1] + entry + "\n" + text[i + 1:]


def git(*args, binary=False):
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout
    return out if binary else out.decode().strip()


def tree_files(rev: str) -> dict[str, bytes]:
    """Every file in `rev` as stored in git (what GitHub's zip holds: no line-ending conversion)."""
    files = {}
    for entry in git("ls-tree", "-r", "-z", rev, binary=True).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        if kind != "blob" or mode == "120000":
            sys.exit(f"Unsupported entry in the tree (symlink or submodule): {path.decode()}")
        files[path.decode()] = git("cat-file", "blob", sha, binary=True)
    return files


def main(argv):
    if len(argv) == 3 and argv[1] == "--verify":
        tag = argv[2]
        version = tag.lstrip("v")
        msg = git("tag", "-l", "--format=%(contents)", tag)
        m = updater.SIGNATURE.search(msg)
        ok = bool(m) and ed25519.verify(updater.PUBLIC_KEY, updater.signed_message(version, tree_files(tag)), base64.b64decode(m.group(1)))
        print(f"{tag}: {'signature OK' if ok else 'NOT validly signed'}")
        return 0 if ok else 1
    if len(argv) != 3:
        print(__doc__)
        return 2
    version, notes = argv[1], argv[2].strip()
    if not updater.parse(version):
        sys.exit(f"Version must look like 1.2.0, not {version!r}")
    if git("status", "--porcelain"):
        sys.exit("Commit or stash your changes first: the release is made from HEAD")
    head_version = git("show", "HEAD:VERSION").strip()
    if head_version != version:
        sys.exit(f"VERSION in HEAD says {head_version}; set it to {version} and commit first")
    tag = f"v{version}"
    if git("tag", "-l", tag):
        sys.exit(f"Tag {tag} already exists")
    if not KEY_FILE.exists():
        sys.exit(f"No release key at {KEY_FILE}; only the maintainer's PC can sign releases")
    seed = bytes.fromhex(dpapi.unprotect(KEY_FILE.read_text("utf-8")))
    if ed25519.public_key(seed) != updater.PUBLIC_KEY:
        sys.exit("The release key doesn't match updater.PUBLIC_KEY")
    existing = CHANGELOG.read_text("utf-8") if CHANGELOG.exists() else ""
    if f"\n## {version} (" not in existing:
        import datetime
        CHANGELOG.write_text(add_to_changelog(existing, changelog_entry(version, datetime.date.today().isoformat(), notes)), "utf-8", newline="\n")
        git("add", "CHANGELOG.md")
        git("commit", "-q", "-m", f"Changelog for {version}")
    sig = ed25519.sign(seed, updater.signed_message(version, tree_files("HEAD")))
    git("tag", "-a", tag, "-m", f"{notes}\n\nOrbi-Signature: {base64.b64encode(sig).decode()}")
    print(f"Created signed tag {tag}. Publish it with: git push origin main --tags")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
