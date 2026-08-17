#!/bin/sh
# Install the nuclei binary + community templates into the image. Run by
# Dockerfile.addons during the client-image overlay (as root). Uses python
# (already present) for download/extract — the hardened base has no curl/git.
# So these heavy assets exist ONLY in images that include the nuclei add-on.
set -e
NUCLEI_VERSION="${NUCLEI_VERSION:-3.8.0}"
NUCLEI_TEMPLATES_TAG="${NUCLEI_TEMPLATES_TAG:-v10.4.2}"
case "$(uname -m)" in
    x86_64) NARCH=amd64 ;;
    aarch64) NARCH=arm64 ;;
    *) NARCH=amd64 ;;
esac

NUCLEI_VERSION="$NUCLEI_VERSION" NUCLEI_TEMPLATES_TAG="$NUCLEI_TEMPLATES_TAG" NARCH="$NARCH" python3 - <<'PY'
import io, os, tarfile, urllib.request, zipfile
v = os.environ["NUCLEI_VERSION"]; tag = os.environ["NUCLEI_TEMPLATES_TAG"]; na = os.environ["NARCH"]

# nuclei binary
bin_url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{v}/nuclei_{v}_linux_{na}.zip"
z = zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(bin_url, timeout=180).read()))
z.extract("nuclei", "/usr/local/bin")
os.chmod("/usr/local/bin/nuclei", 0o755)

# community templates (release tarball, no git needed)
t_url = f"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{tag}.tar.gz"
with tarfile.open(fileobj=io.BytesIO(urllib.request.urlopen(t_url, timeout=600).read())) as t:
    t.extractall("/opt")
PY

# tag archive extracts to /opt/nuclei-templates-<tag-without-leading-v>; normalize
SRC="$(ls -d /opt/nuclei-templates-* 2>/dev/null | head -1)"
[ -n "$SRC" ] && rm -rf /opt/nuclei-templates && mv "$SRC" /opt/nuclei-templates
chown -R surface:surface /opt/nuclei-templates 2>/dev/null || true
echo "✓ nuclei $NUCLEI_VERSION ($NARCH) + templates $NUCLEI_TEMPLATES_TAG installed"
