# TLS-Renewer

> 🌐 [Versão em português](README.pt.md)

Automated TLS certificate renewal driven by a CSR-based webhook API. Runs daily, detects certificates near expiration, requests renewal from the configured API, saves the new certificate, and automatically extracts the chain (intermediate + root) from the PKCS7 response.

Designed for environments where a central CA exposes a webhook accepting CSRs and returning issued certificates plus a PKCS7 chain. Works alongside [TLS-Distributor](https://github.com/wgfreitas/tls-distributor) for end-to-end automation.

---

## Features

- **CSR-driven renewal** — drop a `.csr` in the watched directory; the tool handles the rest.
- **Configurable threshold** — renew only certificates expiring within N days (default: 30).
- **Automatic chain extraction** — parses the PKCS7 response and saves `intermediate.pem` and `root.pem` separately for downstream consumers.
- **Idempotent chain updates** — chain files are only overwritten when their content actually changes.
- **Email notifications** — HTML summary report after each run.
- **CLI flags** — `--force` and `--domain` for manual operations.
- **Scheduled execution** — systemd service and timer included.

---

## Architecture

```
+------------------------------------------------------------------+
|                       Orchestrator host                           |
|                                                                   |
|   tls-renewer.timer (daily, configurable)                         |
|        |                                                          |
|        v                                                          |
|   tls_renewer.py                                                  |
|        |                                                          |
|        +-- 1. Reads CSRs from CSR_DIR                             |
|        +-- 2. For each CSR:                                       |
|        |     +-- Extracts CN                                      |
|        |     +-- Reads existing cert; days until expiry           |
|        |     +-- If close to expiry: POST CSR to API              |
|        |     +-- Saves issued cert to CERT_DIR/<cn>.crt           |
|        |     +-- Extracts intermediate & root from PKCS7          |
|        |         -> CHAIN_DIR/                                    |
|        +-- 3. Sends HTML email summary                            |
|        +-- 4. Logs to LOG_DIR/tls-renewer.log                     |
+------------------------------------------------------------------+
```

---

## Requirements

- Linux (tested on Rocky Linux 9; should work on any modern distribution)
- Python 3.10+
- Network access to the CA webhook URL
- Valid API credentials (`X-API-USER` / `X-API-KEY` headers)
- SMTP server for notifications (optional)

**Python dependencies** (`requirements.txt`):
- `requests` >= 2.31.0
- `cryptography` >= 42.0.0
- `python-dotenv` >= 1.0.0

---

## Installation

```bash
git clone https://github.com/wgfreitas/tls-renewer.git
cd tls-renewer
sudo bash install.sh
```

If the system Python is older than 3.10, point the installer at a newer one:

```bash
sudo PYTHON_BIN=/path/to/python3.11 bash install.sh
```

After installation:

```bash
sudo $EDITOR /opt/tls-renewer/.env
cp /path/to/your/*.csr /opt/tls-renewer/csr/
sudo tls-renew --domain example.com --force
sudo systemctl enable --now tls-renewer.timer
```

---

## Directory layout

```
/opt/tls-renewer/
|-- tls_renewer.py
|-- requirements.txt
|-- venv/
|-- .env                    # chmod 600
|-- csr/                    # Input: CSR files
|-- certs/                  # Output: issued certificates
|   `-- <domain>.distributed   # Marker (used by TLS-Distributor)
`-- chain/
    |-- intermediate.pem
    `-- root.pem

/var/log/tls-renewer/tls-renewer.log
/usr/local/bin/tls-renew
```

---

## Configuration (`.env`)

| Variable | Description | Default |
|---|---|---|
| `CSR_DIR` | Directory containing `.csr` files | `/opt/tls-renewer/csr` |
| `CERT_DIR` | Directory for issued certificates | `/opt/tls-renewer/certs` |
| `CHAIN_DIR` | Directory for extracted chain files | `/opt/tls-renewer/chain` |
| `LOG_DIR` | Log directory | `/var/log/tls-renewer` |
| `API_URL` | Webhook URL | *required* |
| `API_USER` | Header `X-API-USER` | *required* |
| `API_KEY` | Header `X-API-KEY` | *required* |
| `API_TIMEOUT` | HTTP timeout (seconds) | `300` |
| `API_VERIFY_SSL` | Validate API server TLS chain | `true` |
| `RENEW_DAYS_BEFORE` | Days before expiry to renew | `30` |
| `SMTP_HOST` / `PORT` / `USER` / `PASS` | SMTP for notifications | — |
| `EMAIL_FROM` / `EMAIL_TO` | Sender / recipients (comma-separated) | — |

---

## Usage

### Scheduled (systemd timer)

```bash
sudo systemctl enable --now tls-renewer.timer
sudo systemctl list-timers tls-renewer.timer
```

The default timer runs daily at 06:00 (local time) with up to 15 minutes of jitter. To run exactly at 06:00:

```bash
sudo sed -i 's/^RandomizedDelaySec=.*/RandomizedDelaySec=0/' /etc/systemd/system/tls-renewer.timer
sudo systemctl daemon-reload
sudo systemctl restart tls-renewer.timer
```

### Manual (CLI)

```bash
tls-renew                              # Normal: renew only near-expiry certs
tls-renew --force                      # Force renewal of all CSRs
tls-renew --domain example.com         # Process one domain only
tls-renew --domain example.com --force # Force one domain
```

### Logs

```bash
journalctl -u tls-renewer.service --since today
tail -f /var/log/tls-renewer/tls-renewer.log
```

---

## How chain extraction works

The API response is expected to include:

- `certificado_pem_individual` — the issued leaf certificate
- `certificado_cadeia_pkcs7` — the full chain in PKCS7 format

`extract_chain_from_pkcs7()` parses the PKCS7 and classifies each certificate:

- **Root CA**: self-signed (`issuer == subject`) -> saved to `chain/root.pem`
- **Intermediate**: not self-signed, CN contains `"CA"` -> saved to `chain/intermediate.pem`
- **Leaf**: ignored here (already obtained via `certificado_pem_individual`)

Chain files are only rewritten when their content changes, so timestamps remain stable across runs that didn't actually update the chain.

### Adapting to a different API response format

If your API uses different JSON keys, edit `extract_cert_from_response()` in `tls_renewer.py`. The function has fallback logic that scans for common keys (`certificate`, `cert`, `crt`, `pem`, `data`, `result`).

---

## Troubleshooting

### `OSError: [Errno 30] Read-only file system` writing to chain/

The systemd unit uses `ProtectSystem=strict`. Ensure `ReadWritePaths` includes the chain directory:

```
ReadWritePaths=/opt/tls-renewer/certs /opt/tls-renewer/chain /var/log/tls-renewer
```

### `No such file or directory: /opt/tls-renewer/venv/bin/python3`

If the venv was created with a pyenv-installed Python (under `/root/.pyenv/`), systemd's `ProtectHome=yes` will hide it. Set `ProtectHome=no` in the unit (default in this project).

### API returns HTTP 200 with empty body

The API silently accepted the request but returned nothing. Common causes:
- Invalid API key (some APIs return 200 instead of 401 on bad auth)
- IP not whitelisted upstream

Diagnose with cURL:

```bash
jq -Rs '{csr: .}' /opt/tls-renewer/csr/any.csr | \
  curl -ks -D- -X POST "$API_URL" \
    -H "X-API-USER: $API_USER" -H "X-API-KEY: $API_KEY" \
    -H "Content-Type: application/json" -d @-
```

### Notification email not delivered

The SMTP server may silently reject messages with an unauthorized `EMAIL_FROM`. Use an address that is actually authorized to send through your SMTP relay.

---

## Security

- `.env` should have permission `600`, owned by root.
- Never commit `.env` (already in `.gitignore`).
- The systemd unit applies hardening: `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`.
- API credentials never appear in logs (only error categories).

---

## Companion project

[**TLS-Distributor**](https://github.com/wgfreitas/tls-distributor) — distributes certificates produced by this tool to remote web servers via SSH/SFTP, handles backups, ownership, and triggers service reloads.

---

## Origin

Originally developed at SINFO/IRR/Fiocruz (Instituto René Rachou, Brazil) to automate TLS renewal across an internal infrastructure of ~65 web servers using an organizational webhook-based CA. Generalized and released as open source under MIT.

---

## License

MIT — see [LICENSE](LICENSE).
