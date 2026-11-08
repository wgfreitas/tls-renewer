# Changelog

Todas as mudanças notáveis neste projeto serão documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/),
e o projeto adere ao [Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-06-15

### Added

- **Validação certificado × CSR** (`cert_matches_csr()`): antes de salvar,
  o certificado retornado pela API é validado contra o CSR enviado:
  - Public key do certificado deve ser idêntica à do CSR (comparação em
    DER/SubjectPublicKeyInfo — uniforme para RSA, EC, Ed25519)
  - CN do certificado deve corresponder ao CN do CSR
  - Em caso de divergência, o certificado é rejeitado, o erro é logado e
    reportado por e-mail, e o certificado atual (ainda válido) permanece
    em uso — falha contida em vez de outage distribuído
- **Lock exclusivo contra execução concorrente** (`acquire_lock()` via
  `fcntl.flock`): impede que execução manual e timer systemd rodem
  simultaneamente, o que poderia intercalar escritas em `chain/` e nos
  markers `.distributed`. Liberação automática pelo kernel na morte do
  processo (sem stale locks). Configurável via `LOCK_FILE`
  (padrão: `/run/tls-renewer/renewer.lock`)
- Unit systemd atualizada com `RuntimeDirectory=tls-renewer` e
  `RuntimeDirectoryPreserve=yes` (necessário para o lock file conviver
  com `ProtectSystem=strict`)

## [1.0.1] - 2026-06-15

### Added

- Retry automático com backoff exponencial na chamada à API
  (`make_session_with_retries()` via `urllib3.Retry`):
  - Cobre falhas de conexão (connection reset, DNS, TCP), falhas de
    leitura durante transmissão e respostas HTTP 5xx
  - Configurável via `API_RETRY_TOTAL` (padrão: 3) e
    `API_RETRY_BACKOFF` (padrão: 1 → esperas de 1s, 2s, 4s)
- Novas variáveis documentadas no `.env.example`

### Fixed

- Falha transiente de rede (`ConnectionResetError(104)`) derrubava a
  renovação de um domínio sem nova tentativa, exigindo intervenção
  manual

## [1.0.0] - 2026-05-19

### Initial public release

- Renovação automática de certificados TLS via API webhook
- Verificação de expiração via leitura PEM com `cryptography.x509`
- Limiar configurável de renovação (padrão 30 dias)
- Extração automática de intermediate e root do PKCS7 retornado pela API
- Notificação por e-mail HTML com resumo das renovações
- CLI com `--force` e `--domain`
- Wrapper `tls-renew` em `/usr/local/bin/`
- systemd service + timer para execução diária
- Logging estruturado em `/var/log/tls-renewer/`
- Idempotência — chain files só são reescritos se conteúdo mudou
