#!/bin/bash
# =============================================================================
# tls-renewer — Installation script
# Run as root from the cloned repository directory
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/tls-renewer"
LOG_DIR="/var/log/tls-renewer"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root (use sudo)" >&2
    exit 1
fi

echo "=== tls-renewer installation ==="

# 1. Directories
echo "[1/6] Creating directories..."
mkdir -p "${INSTALL_DIR}"/{csr,certs,chain}
mkdir -p "${LOG_DIR}"

# 2. Copy files
echo "[2/6] Copying files..."
cp "${SCRIPT_DIR}/tls_renewer.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
chmod 755 "${INSTALL_DIR}/tls_renewer.py"

# 3. .env (preserve existing)
echo "[3/6] Configuring .env..."
if [ ! -f "${INSTALL_DIR}/.env" ]; then
    cp "${SCRIPT_DIR}/.env.example" "${INSTALL_DIR}/.env"
    chmod 600 "${INSTALL_DIR}/.env"
    echo "    ⚠  .env created from template — EDIT with your credentials!"
else
    echo "    ✓  .env already exists — kept"
fi

# 4. Python virtualenv
echo "[4/6] Creating Python virtualenv..."
# Use python3 from $PATH (works with pyenv too)
PYTHON_BIN="$(command -v python3)"
if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: python3 not found in PATH" >&2
    exit 1
fi
echo "    Using: $PYTHON_BIN ($($PYTHON_BIN --version))"

"$PYTHON_BIN" -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip -q
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q

# 5. CLI wrapper
echo "[5/6] Installing CLI wrapper..."
cp "${SCRIPT_DIR}/tls-renew" /usr/local/bin/tls-renew
chmod 755 /usr/local/bin/tls-renew

# 6. systemd
echo "[6/6] Installing systemd units..."
cp "${SCRIPT_DIR}/tls-renewer.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/tls-renewer.timer" /etc/systemd/system/
systemctl daemon-reload
echo "    ℹ  Units installed but NOT enabled."
echo "    ℹ  Enable with: systemctl enable --now tls-renewer.timer"

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit credentials:        nano ${INSTALL_DIR}/.env"
echo "  2. Place .csr files in:     ${INSTALL_DIR}/csr/"
echo "  3. Test manually:           tls-renew --domain your.example.org --force"
echo "  4. Enable daily timer:      systemctl enable --now tls-renewer.timer"
echo "  5. View next run:           systemctl list-timers tls-renewer.timer"
echo ""
