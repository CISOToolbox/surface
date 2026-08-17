# smb_scan_rs — SMB file-share scanner (Rust worker)

High-throughput, out-of-process variant of the `smb_scan` add-on. The Python
shim (`smb_scan_rs.py`) registers `smb_scan_rs` and runs the compiled Rust
binary `bin/ciso-smb-scan` as a **separate process** (no GIL contention → the
app stays responsive during big scans; native speed + fast regex).

## Build the binary (required before packaging an image)
```bash
bash rust/build.sh        # -> bin/ciso-smb-scan (host arch, bookworm ABI)
```
The binary is arch-specific and **not committed** (`bin/.gitignore`). For a
multi-arch GHCR image, build it once per target platform.

## Package into a client image
```bash
shared/build-client-image.sh <client> --module surface --addons generic/smb_scan_rs
```
`Dockerfile.addons` installs the runtime lib from `apt-packages.txt`
(`libsmbclient`) and makes `bin/*` executable.

## Scope vs the Python `smb_scan`
Same finding schema, secret ruleset, masking, caps (max_files / time_budget_s)
and host roll-up. **Covered:** text/config/code + Office bodies (docx/xlsx/pptx).
**Not covered:** PDF body extraction (no pdfminer-grade Rust crate) — PDFs are
flagged by name only. Use the Python `smb_scan` add-on when PDF bodies matter.
