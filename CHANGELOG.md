# Changelog

Todas as mudanças notáveis neste projeto serão documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/),
e o projeto adere ao [Semantic Versioning](https://semver.org/).

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
