#!/usr/bin/env python3
"""
TLS Certificate Auto-Renewer for Fiocruz
=========================================
Monitora certificados TLS, renova automaticamente via API webhook,
extrai cadeia (intermediate/root) do PKCS7, e notifica por e-mail.

Autor: Wagner Freitas (SINFO/IRR/Fiocruz)
"""

import argparse
import json
import logging
import os
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7 as pkcs7_module
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

# Diretórios
CSR_DIR = Path(os.getenv("CSR_DIR", "/opt/tls-renewer/csr"))
CERT_DIR = Path(os.getenv("CERT_DIR", "/opt/tls-renewer/certs"))
CHAIN_DIR = Path(os.getenv("CHAIN_DIR", "/opt/tls-renewer/chain"))
LOG_DIR = Path(os.getenv("LOG_DIR", "/var/log/tls-renewer"))

# API
API_URL = os.getenv("API_URL", "https://tls.fiocruz.br/webhook/certificado")
API_USER = os.getenv("API_USER")
API_KEY = os.getenv("API_KEY")
API_TIMEOUT = int(os.getenv("API_TIMEOUT", "300"))
API_VERIFY_SSL = os.getenv("API_VERIFY_SSL", "false").lower() == "true"

# Renovação
RENEW_DAYS_BEFORE = int(os.getenv("RENEW_DAYS_BEFORE", "30"))

# E-mail (SMTP)
SMTP_HOST = os.getenv("SMTP_HOST", "smtps.fiocruz.br")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "tls-renewer@minas.fiocruz.br")
EMAIL_TO = os.getenv("EMAIL_TO", "")

# Logging
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "tls-renewer.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("tls-renewer")


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------


def validate_config():
    """Valida variáveis obrigatórias antes de prosseguir."""
    erros = []
    if not API_USER:
        erros.append("API_USER não definido")
    if not API_KEY:
        erros.append("API_KEY não definido")
    if not CSR_DIR.is_dir():
        erros.append(f"Diretório de CSRs não encontrado: {CSR_DIR}")
    if erros:
        for e in erros:
            log.error(e)
        sys.exit(1)

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    CHAIN_DIR.mkdir(parents=True, exist_ok=True)


def extract_cn_from_csr(csr_path: Path) -> str:
    """Extrai o Common Name (CN) do arquivo CSR."""
    try:
        csr_pem = csr_path.read_bytes()
        csr_obj = x509.load_pem_x509_csr(csr_pem)
        cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception as exc:
        log.warning("Não foi possível extrair CN de %s: %s", csr_path.name, exc)
    return csr_path.stem


def get_cert_expiry(cert_path: Path) -> datetime | None:
    """Retorna a data de expiração de um certificado PEM existente."""
    try:
        cert_pem = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        return cert.not_valid_after_utc
    except Exception as exc:
        log.warning("Erro ao ler certificado %s: %s", cert_path.name, exc)
        return None


def cert_needs_renewal(cert_path: Path) -> bool:
    """Retorna True se o certificado não existe ou está próximo a vencer."""
    if not cert_path.exists():
        return True
    expiry = get_cert_expiry(cert_path)
    if expiry is None:
        return True
    threshold = datetime.now(timezone.utc) + timedelta(days=RENEW_DAYS_BEFORE)
    remaining = (expiry - datetime.now(timezone.utc)).days
    if expiry <= threshold:
        log.info(
            "Certificado %s expira em %d dias (limiar: %d) — marcado para renovação",
            cert_path.name, remaining, RENEW_DAYS_BEFORE,
        )
        return True
    log.info(
        "Certificado %s OK — expira em %d dias (%s)",
        cert_path.name, remaining, expiry.strftime("%Y-%m-%d %H:%M UTC"),
    )
    return False


def request_certificate(csr_content: str) -> dict:
    """Envia CSR para a API e retorna o JSON de resposta."""
    headers = {
        "Content-Type": "application/json",
        "X-API-USER": API_USER,
        "X-API-KEY": API_KEY,
    }
    payload = {"csr": csr_content}

    resp = requests.post(
        API_URL,
        headers=headers,
        json=payload,
        timeout=API_TIMEOUT,
        verify=API_VERIFY_SSL,
    )
    resp.raise_for_status()
    return resp.json()


def save_certificate(domain: str, cert_data: str) -> Path:
    """Salva o certificado retornado em CERT_DIR/<domain>.crt (sobrescreve)."""
    safe_name = domain.replace("*", "_wildcard").replace(" ", "_")
    cert_path = CERT_DIR / f"{safe_name}.crt"
    cert_path.write_text(cert_data, encoding="utf-8")
    cert_path.chmod(0o644)
    log.info("Certificado salvo: %s", cert_path)
    return cert_path


# ---------------------------------------------------------------------------
# Extração de cadeia PKCS7
# ---------------------------------------------------------------------------


def extract_chain_from_pkcs7(pkcs7_pem: str) -> dict:
    """
    Extrai certificados individuais da cadeia PKCS7 retornada pela API.

    A cadeia PKCS7 da API Fiocruz contém:
      [0] Certificado do servidor (leaf)
      [1] Certificado intermediário (RNP ICPEdu)
      [2] Certificado raiz (GlobalSign Root R46) — se presente

    Retorna dict com chaves: 'intermediate', 'root' (podem ser None).
    """
    result = {"intermediate": None, "root": None}

    try:
        certs = pkcs7_module.load_pem_pkcs7_certificates(pkcs7_pem.encode("utf-8"))
        if not certs:
            log.warning("PKCS7 vazio — nenhum certificado na cadeia")
            return result

        for cert in certs:
            pem = cert.public_bytes(Encoding.PEM).decode("utf-8")
            issuer = cert.issuer
            subject = cert.subject
            cn_list = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = cn_list[0].value if cn_list else "???"

            # Self-signed (issuer == subject) → root CA
            if issuer == subject:
                result["root"] = pem
                log.info("  Chain: Root CA → %s", cn)
            # CN contém "CA" → intermediate
            elif "CA" in cn.upper():
                result["intermediate"] = pem
                log.info("  Chain: Intermediate → %s", cn)
            # else: leaf (servidor) — já temos via certificado_pem_individual

    except Exception as exc:
        log.warning("Erro ao extrair cadeia PKCS7: %s", exc)

    return result


def save_chain_files(chain: dict):
    """
    Salva intermediate.pem e root.pem extraídos da cadeia PKCS7.
    Só sobrescreve se o conteúdo mudou.
    """
    for name in ("intermediate", "root"):
        content = chain.get(name)
        if not content:
            continue

        filepath = CHAIN_DIR / f"{name}.pem"

        # Só sobrescreve se mudou
        if filepath.exists():
            existing = filepath.read_text(encoding="utf-8").strip()
            if existing == content.strip():
                continue

        filepath.write_text(content, encoding="utf-8")
        filepath.chmod(0o644)
        log.info("Chain atualizada: %s", filepath)


# ---------------------------------------------------------------------------
# Extração de certificado da resposta da API
# ---------------------------------------------------------------------------


def extract_cert_from_response(response_data: dict) -> tuple[str | None, dict]:
    """
    Extrai o certificado PEM individual E a cadeia da resposta da API.

    Retorna: (cert_pem, chain_dict)
    """
    cert_pem = None
    chain = {"intermediate": None, "root": None}

    # 1. Extrai certificado individual
    if "certificado_pem_individual" in response_data:
        val = response_data["certificado_pem_individual"].strip()
        if "BEGIN CERTIFICATE" in val:
            log.info(
                "Pedido: %s | CN: %s",
                response_data.get("pedido", "N/A"),
                response_data.get("common_name", "N/A"),
            )
            cert_pem = val

    # 2. Extrai cadeia do PKCS7
    if "certificado_cadeia_pkcs7" in response_data:
        pkcs7_pem = response_data["certificado_cadeia_pkcs7"].strip()
        if "BEGIN PKCS7" in pkcs7_pem:
            chain = extract_chain_from_pkcs7(pkcs7_pem)

    # Fallback para chaves genéricas
    if not cert_pem:
        for key in ("certificate", "cert", "crt", "pem", "data", "result"):
            if key in response_data and isinstance(response_data[key], str):
                val = response_data[key].strip()
                if "BEGIN CERTIFICATE" in val:
                    cert_pem = val
                    break

    return cert_pem, chain


# ---------------------------------------------------------------------------
# Lógica principal
# ---------------------------------------------------------------------------


def process_csr(csr_path: Path, force: bool = False) -> tuple[bool, str, str]:
    """
    Processa um arquivo CSR: verifica necessidade, envia para API, salva.

    Args:
        csr_path: Caminho do arquivo CSR.
        force: Se True, força renovação mesmo se cert ainda válido.

    Retorna: (sucesso: bool, domínio: str, mensagem: str)
    """
    domain = extract_cn_from_csr(csr_path)
    safe_name = domain.replace("*", "_wildcard").replace(" ", "_")
    cert_path = CERT_DIR / f"{safe_name}.crt"

    if not force and not cert_needs_renewal(cert_path):
        return True, domain, "Não necessita renovação"

    if force:
        log.info("Renovação forçada para: %s (CSR: %s)", domain, csr_path.name)
    else:
        log.info("Renovando certificado para: %s (CSR: %s)", domain, csr_path.name)

    # Lê CSR
    csr_content = csr_path.read_text(encoding="utf-8").strip()
    if "BEGIN CERTIFICATE REQUEST" not in csr_content:
        return False, domain, "Arquivo CSR inválido (sem header PEM)"

    # Envia para API
    try:
        response = request_certificate(csr_content)
    except requests.exceptions.HTTPError as exc:
        return False, domain, f"Erro HTTP: {exc.response.status_code} — {exc.response.text[:200]}"
    except requests.exceptions.RequestException as exc:
        return False, domain, f"Erro de conexão: {exc}"

    # Extrai certificado e cadeia da resposta
    cert_pem, chain = extract_cert_from_response(response)
    if not cert_pem:
        log.warning(
            "Resposta da API (chaves): %s",
            list(response.keys()) if isinstance(response, dict) else type(response),
        )
        return False, domain, (
            f"Certificado não encontrado na resposta da API. "
            f"Chaves retornadas: {list(response.keys()) if isinstance(response, dict) else 'N/A'}"
        )

    # Salva certificado
    saved_path = save_certificate(domain, cert_pem)

    # Salva/atualiza chain files (intermediate.pem, root.pem)
    save_chain_files(chain)

    return True, domain, str(saved_path)


# ---------------------------------------------------------------------------
# Notificação por e-mail
# ---------------------------------------------------------------------------


def send_notification(renewed: list[dict], errors: list[dict]):
    """Envia e-mail resumo das renovações realizadas (e erros, se houver)."""
    recipients = [e.strip() for e in EMAIL_TO.split(",") if e.strip()]

    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS and recipients):
        log.warning("SMTP não totalmente configurado — notificação não enviada.")
        return
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    subject = f"[TLS-Renewer] Relatório de Renovação — {now_str}"

    html_parts = [
        "<html><body>",
        "<h2>TLS Certificate Auto-Renewer — Relatório</h2>",
        f"<p><strong>Execução:</strong> {now_str}</p>",
    ]

    if renewed:
        html_parts.append("<h3>✅ Certificados Renovados</h3><ul>")
        for item in renewed:
            html_parts.append(
                f'<li><strong>{item["domain"]}</strong> — '
                f'salvo em <code>{item["path"]}</code></li>'
            )
        html_parts.append("</ul>")
        html_parts.append(
            "<p><em>Ação necessária:</em> configurar manualmente os serviços "
            "web (Apache/Nginx) com os novos certificados.</p>"
        )

    if errors:
        html_parts.append("<h3>❌ Erros</h3><ul>")
        for item in errors:
            html_parts.append(
                f'<li><strong>{item["domain"]}</strong> — {item["error"]}</li>'
            )
        html_parts.append("</ul>")

    if not renewed and not errors:
        html_parts.append(
            "<p>Nenhum certificado necessita renovação no momento.</p>"
        )

    html_parts.append(
        "<hr><p style='color:#888;font-size:0.9em;'>"
        "Mensagem automática gerada pelo TLS-Renewer (SINFO/IRR).</p>"
    )
    html_parts.append("</body></html>")

    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText("\n".join(html_parts), "html"))

    try:
        context = ssl.create_default_context()

        log.info("Conectando ao SMTP: %s:%d", SMTP_HOST, SMTP_PORT)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            log.info("E-mail de notificação enviado para: %s", ", ".join(recipients))

    except smtplib.SMTPAuthenticationError as exc:
        log.error("Falha de autenticação SMTP: %s", exc)
    except smtplib.SMTPException as exc:
        log.error("Erro SMTP: %s", exc)
    except Exception as exc:
        log.error("Falha ao enviar e-mail: %s", exc)


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------


def main():
    """Ponto de entrada principal."""
    parser = argparse.ArgumentParser(
        description="TLS Certificate Auto-Renewer — SINFO/IRR/Fiocruz",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s                                   Execução normal (renova só o que vence)
  %(prog)s --force                           Força renovação de TODOS os CSRs
  %(prog)s --domain redcap.minas.fiocruz.br  Processa apenas 1 domínio (se vencendo)
  %(prog)s --domain redcap.minas.fiocruz.br --force   Força renovação de 1 domínio
        """,
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Força renovação mesmo se certificado ainda válido",
    )
    parser.add_argument(
        "--domain", type=str, default=None,
        help="Renova apenas o domínio especificado (CN do CSR)",
    )
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("TLS-Renewer iniciado%s", " (FORCE)" if args.force else "")
    log.info("CSR_DIR: %s", CSR_DIR)
    log.info("CERT_DIR: %s", CERT_DIR)
    log.info("CHAIN_DIR: %s", CHAIN_DIR)
    log.info("Limiar de renovação: %d dias", RENEW_DAYS_BEFORE)
    if args.domain:
        log.info("Filtro de domínio: %s", args.domain)
    log.info("=" * 60)

    validate_config()

    csr_files = sorted(CSR_DIR.glob("*.csr"))
    if not csr_files:
        log.warning("Nenhum arquivo .csr encontrado em %s", CSR_DIR)
        return

    # Filtro por domínio (se especificado)
    if args.domain:
        csr_files = [c for c in csr_files if extract_cn_from_csr(c) == args.domain]
        if not csr_files:
            log.error("Domínio '%s' não encontrado nos CSRs disponíveis", args.domain)
            sys.exit(1)

    log.info("Encontrados %d arquivo(s) CSR", len(csr_files))

    renewed: list[dict] = []
    errors: list[dict] = []

    for csr_path in csr_files:
        success, domain, message = process_csr(csr_path, force=args.force)
        if not success:
            log.error("FALHA [%s]: %s", domain, message)
            errors.append({"domain": domain, "error": message})
        elif "Não necessita" in message:
            log.info("SKIP [%s]: %s", domain, message)
        else:
            log.info("OK [%s]: %s", domain, message)
            renewed.append({"domain": domain, "path": message})

    if renewed or errors:
        send_notification(renewed, errors)

    log.info("TLS-Renewer finalizado. Renovados: %d | Erros: %d", len(renewed), len(errors))


if __name__ == "__main__":
    main()
