#!/bin/sh
# Install the nuclei binary + community templates into the image. Run by
# Dockerfile.addons during the client-image overlay (as root). Uses python
# (already present) for download/extract — the hardened base has no curl/git.
# So these heavy assets exist ONLY in images that include the nuclei add-on.
set -e
NUCLEI_VERSION="${NUCLEI_VERSION:-3.11.1}"
# Official sha256 of the release zips (nuclei_<version>_checksums.txt), checked
# before extraction. MUST be updated together with NUCLEI_VERSION.
NUCLEI_SHA256_AMD64="${NUCLEI_SHA256_AMD64:-ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6}"
NUCLEI_SHA256_ARM64="${NUCLEI_SHA256_ARM64:-8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07}"
NUCLEI_TEMPLATES_TAG="${NUCLEI_TEMPLATES_TAG:-v10.4.2}"
# Official sha256 of the templates archive (nuclei-templates-<tag>_checksums.txt
# on the templates release), checked the same way. MUST be updated together
# with NUCLEI_TEMPLATES_TAG.
NUCLEI_TEMPLATES_SHA256="${NUCLEI_TEMPLATES_SHA256:-5f416b77da1397adb0e19aedf1b2744dc715673465c64b3031b53ad31a1bf6c9}"
case "$(uname -m)" in
    x86_64) NARCH=amd64; NSHA="$NUCLEI_SHA256_AMD64" ;;
    aarch64) NARCH=arm64; NSHA="$NUCLEI_SHA256_ARM64" ;;
    *) echo "nuclei: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

NUCLEI_VERSION="$NUCLEI_VERSION" NUCLEI_TEMPLATES_TAG="$NUCLEI_TEMPLATES_TAG" NARCH="$NARCH" NSHA="$NSHA" TSHA="$NUCLEI_TEMPLATES_SHA256" python3 - <<'PY'
import hashlib, io, os, tarfile, urllib.request, zipfile
v = os.environ["NUCLEI_VERSION"]; tag = os.environ["NUCLEI_TEMPLATES_TAG"]; na = os.environ["NARCH"]

# nuclei binary
bin_url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{v}/nuclei_{v}_linux_{na}.zip"
data = urllib.request.urlopen(bin_url, timeout=180).read()
if hashlib.sha256(data).hexdigest() != os.environ["NSHA"]:
    raise SystemExit(f"nuclei {v} ({na}): sha256 mismatch — refusing the download")
z = zipfile.ZipFile(io.BytesIO(data))
z.extract("nuclei", "/usr/local/bin")
os.chmod("/usr/local/bin/nuclei", 0o755)

# community templates (release tarball, no git needed)
t_url = f"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{tag}.tar.gz"
tdata = urllib.request.urlopen(t_url, timeout=600).read()
if hashlib.sha256(tdata).hexdigest() != os.environ["TSHA"]:
    raise SystemExit(f"nuclei templates {tag}: sha256 mismatch — refusing the download")
with tarfile.open(fileobj=io.BytesIO(tdata)) as t:
    t.extractall("/opt", filter="data")
PY

# tag archive extracts to /opt/nuclei-templates-<tag-without-leading-v>; normalize
SRC="$(ls -d /opt/nuclei-templates-* 2>/dev/null | head -1)"
[ -n "$SRC" ] && rm -rf /opt/nuclei-templates && mv "$SRC" /opt/nuclei-templates
chown -R surface:surface /opt/nuclei-templates 2>/dev/null || true
echo "✓ nuclei $NUCLEI_VERSION ($NARCH) + templates $NUCLEI_TEMPLATES_TAG installed"
