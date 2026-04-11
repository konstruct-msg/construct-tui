#!/usr/bin/env sh
# konstrukt — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/construct-tui/main/scripts/install.sh | sh
set -e

REPO="YOUR_ORG/construct-tui"
BIN="konstrukt"
INSTALL_DIR="${KONSTRUKT_INSTALL_DIR:-/usr/local/bin}"

# ── Detect platform ──────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64)  ASSET="${BIN}-linux-x86_64.tar.gz" ;;
      aarch64) ASSET="${BIN}-linux-aarch64.tar.gz" ;;
      *)       echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64)  ASSET="${BIN}-macos-arm64.tar.gz" ;;
      x86_64) ASSET="${BIN}-macos-x86_64.tar.gz" ;;
      *)      echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

# ── Fetch latest release tag ─────────────────────────────────────────────────
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "Could not fetch latest release tag from GitHub." >&2
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"

echo "Installing ${BIN} ${LATEST} for ${OS}/${ARCH}..."
echo "  -> ${URL}"

# ── Download & install ───────────────────────────────────────────────────────
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "${TMP}/${ASSET}"
tar -xzf "${TMP}/${ASSET}" -C "$TMP"

NEEDS_SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
  NEEDS_SUDO="sudo"
fi

$NEEDS_SUDO install -m 755 "${TMP}/${BIN}-"* "${INSTALL_DIR}/${BIN}"

echo ""
echo "  ✓ ${BIN} installed to ${INSTALL_DIR}/${BIN}"
echo "  Run: ${BIN} --help"
