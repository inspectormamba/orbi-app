r"""Regenerates requirements.txt from requirements.in: every dependency (including indirect ones)
pinned to one version, with the SHA-256 of every file PyPI publishes for it.

    .venv\Scripts\python scripts\lock_requirements.py
"""
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet",
                        "--report", str(report), "-r", str(ROOT / "requirements.in")], check=True)
        installs = json.loads(report.read_text("utf-8"))["install"]
    pins = sorted(((i["metadata"]["name"], i["metadata"]["version"]) for i in installs), key=lambda x: x[0].lower())
    lines = ["# Every dependency, pinned with its published SHA-256 hashes (pip then refuses anything else).",
             "# Generated from requirements.in by scripts/lock_requirements.py; don't edit by hand.", ""]
    for name, version in pins:
        data = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30))
        hashes = sorted({u["digests"]["sha256"] for u in data["urls"]})
        lines.append(f"{name}=={version} \\")
        lines += [f"    --hash=sha256:{h}" + (" \\" if i < len(hashes) - 1 else "") for i, h in enumerate(hashes)]
    (ROOT / "requirements.txt").write_text("\n".join(lines) + "\n", "utf-8", newline="\n")
    print(f"requirements.txt: {len(pins)} packages")


if __name__ == "__main__":
    main()
