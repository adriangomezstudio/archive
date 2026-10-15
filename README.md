# The Archive

Password-protected catalogue of Adrian Gomez's paintings, served by GitHub Pages at archive.adriangomezstudio.com.

Everything here is encrypted (AES-256-GCM, key derived from the password with PBKDF2-SHA256). The repository is public, but `data.bin` and every file in `e/` are unreadable without the password. The password is never stored in this repo.

## Updating
The source of truth is The Archive artifact on claude.ai. To publish changes:
1. Export its `data/archive.json`, `web/*.jpg` and `wip/*.jpg` into a folder.
2. `ARCHIVE_PASSWORD='…' python3 tools/build.py <that folder>` (requires `cryptography` and `Pillow`).
3. Commit and push. `vault.json` keeps the same salt so saved sign-ins keep working; changing the password signs everyone out.
