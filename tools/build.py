#!/usr/bin/env python3
"""Build the encrypted Archive site.

Usage:
  ARCHIVE_PASSWORD='...' python3 tools/build.py SRC_DIR

SRC_DIR holds the plain source exported from The Archive artifact:
  data/archive.json, web/<id>.jpg, wip/<id>.jpg

Everything published in this repo is encrypted with AES-256-GCM using a key
derived from the password (PBKDF2-SHA256). Without the password the data file
and every image are unreadable, even though the repository is public.
The password is never written to the repo.
"""
import base64, hashlib, hmac, io, json, os, shutil, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parent.parent
ITER = 310000
THUMB = 640


def derive(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())


def seal(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def thumb_bytes(path: Path) -> bytes:
    im = ImageOps.exif_transpose(Image.open(path)).convert("RGB")
    im.thumbnail((THUMB, THUMB), Image.LANCZOS)
    buf = io.BytesIO(); im.save(buf, "JPEG", quality=82, optimize=True, progressive=True)
    return buf.getvalue()


def main():
    src = Path(sys.argv[1])
    pw = os.environ.get("ARCHIVE_PASSWORD")
    if not pw:
        sys.exit("Set ARCHIVE_PASSWORD")
    vault_path = ROOT / "vault.json"
    vault = json.loads(vault_path.read_text()) if vault_path.exists() else {}
    salt = base64.b64decode(vault["salt"]) if "salt" in vault else os.urandom(16)
    key = derive(pw, salt)
    namer = lambda name: hmac.new(key, name.encode(), hashlib.sha256).hexdigest()[:24] + ".bin"

    data = json.loads((src / "data/archive.json").read_text())
    out = ROOT / "e"
    if out.exists(): shutil.rmtree(out)
    out.mkdir()

    files = {}
    def add(name, raw):
        fn = namer(name); (out / fn).write_bytes(seal(key, raw)); files[name] = fn

    ids = [p for w in data["works"] for p in w["photos"]]
    for pid in ids:
        f = src / "web" / (pid + ".jpg")
        add("web/" + pid, f.read_bytes()); add("thumb/" + pid, thumb_bytes(f))
    for w in data.get("wip", []):
        f = src / w["photo"]
        add("web/" + w["photo"], f.read_bytes()); add("thumb/" + w["photo"], thumb_bytes(f))

    public = {"works": data["works"], "wip": data.get("wip", []), "files": files, "savedAt": data.get("savedAt")}
    (ROOT / "data.bin").write_bytes(seal(key, json.dumps(public, ensure_ascii=False).encode()))
    vault_path.write_text(json.dumps({"salt": base64.b64encode(salt).decode(), "iterations": ITER}, indent=1) + "\n")
    print(f"{len(ids)} archive photos, {len(data.get('wip', []))} WIP photos, {len(files)} encrypted files")


if __name__ == "__main__":
    main()
