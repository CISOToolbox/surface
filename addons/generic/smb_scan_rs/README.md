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
tools/build-client-image.sh <client> --module surface --addons generic/smb_scan_rs
```
`Dockerfile.addons` installs the runtime lib from `apt-packages.txt`
(`libsmbclient`) and makes `bin/*` executable.

## Scope vs the Python `smb_scan`
Same finding schema, secret ruleset, masking, caps (max_files / time_budget_s)
and host roll-up. **Covered:** text/config/code + Office bodies (docx/xlsx/pptx).
**Not covered:** PDF body extraction (no pdfminer-grade Rust crate) — PDFs are
flagged by name only. Use the Python `smb_scan` add-on when PDF bodies matter.
Office documents are inflated within a 100 MB budget per file (a few MB of zip
can inflate to gigabytes) and a pptx is read up to 5,000 slides: past either,
what was read is still scanned and the file is reported with an
`smb_truncated` finding (`truncated_files` in the final `scanner_state`
record). Workbooks are read as XML (shared strings, then sheets), without a
spreadsheet library, whose cell ranges can allocate gigabytes from a tiny
file. Measured peak: about 535 MB per document at worst.
