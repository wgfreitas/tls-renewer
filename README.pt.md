# TLS-Renewer

> 🌐 [English version](README.md)

Renovação automática de certificados TLS via API webhook baseada em CSR. Executa diariamente, detecta certificados próximos a vencer, solicita renovação à API configurada, salva o certificado emitido e extrai automaticamente a cadeia (intermediate + root) da resposta PKCS7.

Projetado para ambientes onde uma CA central expõe um webhook que aceita CSRs e retorna certificados emitidos acompanhados de cadeia PKCS7. Funciona junto com o [TLS-Distributor](https://github.com/wgfreitas/tls-distributor) para automação ponta a ponta.

---

## Recursos

- **Renovação baseada em CSR** — coloque um `.csr` no diretório monitorado; a ferramenta cuida do resto.
- **Limiar configurável** — renova apenas certificados que vencem em N dias (padrão: 30).
- **Extração automática da cadeia** — analisa a resposta PKCS7 e salva `intermediate.pem` e `root.pem` separadamente para uso por outros consumidores.
- **Atualização idempotente da cadeia** — arquivos de cadeia só são sobrescritos quando o conteúdo realmente muda.
- **Retry automático** — falhas transientes de rede (connection reset, 5xx) são repetidas com backoff exponencial.
- **Validação certificado ↔ CSR** — o certificado retornado é rejeitado se a public key e o CN não corresponderem ao CSR, impedindo que um certificado trocado chegue aos seus servidores.
- **Lock de concorrência** — lock via `flock` impede sobreposição entre execução manual e timer.
- **Notificações por e-mail** — relatório HTML após cada execução.
- **Flags de CLI** — `--force` e `--domain` para operações manuais.
- **Execução agendada** — service e timer systemd incluídos.

---

## Arquitetura

```
+------------------------------------------------------------------+
|                       Servidor orquestrador                       |
|                                                                   |
|   tls-renewer.timer (diário, configurável)                        |
|        |                                                          |
|        v                                                          |
|   tls_renewer.py                                                  |
|        |                                                          |
|        +-- 1. Lê CSRs do CSR_DIR                                  |
|        +-- 2. Para cada CSR:                                      |
|        |     +-- Extrai o CN                                      |
|        |     +-- Lê cert existente; dias até vencer               |
|        |     +-- Se próximo do vencimento: POST do CSR para a API |
|        |     +-- Salva cert emitido em CERT_DIR/<cn>.crt          |
|        |     +-- Extrai intermediate e root do PKCS7              |
|        |         -> CHAIN_DIR/                                    |
|        +-- 3. Envia e-mail HTML resumo                            |
|        +-- 4. Loga em LOG_DIR/tls-renewer.log                     |
+------------------------------------------------------------------+
```

---

## Requisitos

- Linux (testado em Rocky Linux 9; deve funcionar em qualquer distribuição moderna)
- Python 3.10+
- Acesso de rede à URL do webhook
- Credenciais válidas da API (`X-API-USER` / `X-API-KEY`)
- Servidor SMTP para notificações (opcional)

**Dependências Python** (`requirements.txt`):
- `requests` >= 2.31.0
- `cryptography` >= 42.0.0
- `python-dotenv` >= 1.0.0

---

## Instalação

```bash
git clone https://github.com/wgfreitas/tls-renewer.git
cd tls-renewer
sudo bash install.sh
```

Se o Python do sistema for anterior à 3.10, aponte o instalador para uma versão mais recente (ex: pyenv):

```bash
sudo PATH=/root/.pyenv/versions/3.11.9/bin:$PATH bash install.sh
```

Após a instalação:

```bash
sudo $EDITOR /opt/tls-renewer/.env       # Configure credenciais e SMTP
cp /caminho/para/seus/*.csr /opt/tls-renewer/csr/
sudo tls-renew --domain seudominio.example.org --force   # Teste
sudo systemctl enable --now tls-renewer.timer            # Habilita execução diária
```

---

## Estrutura de diretórios

```
/opt/tls-renewer/
|-- tls_renewer.py
|-- requirements.txt
|-- venv/
|-- .env                    # chmod 600
|-- csr/                    # Entrada: arquivos CSR
|-- certs/                  # Saída: certificados emitidos
|   `-- <dominio>.distributed   # Marker (usado pelo TLS-Distributor)
`-- chain/
    |-- intermediate.pem
    `-- root.pem

/var/log/tls-renewer/tls-renewer.log
/usr/local/bin/tls-renew
```

---

## Configuração (`.env`)

| Variável | Descrição | Padrão |
|---|---|---|
| `CSR_DIR` | Diretório com arquivos `.csr` | `/opt/tls-renewer/csr` |
| `CERT_DIR` | Diretório para certificados emitidos | `/opt/tls-renewer/certs` |
| `CHAIN_DIR` | Diretório para arquivos de cadeia extraídos | `/opt/tls-renewer/chain` |
| `LOG_DIR` | Diretório de logs | `/var/log/tls-renewer` |
| `API_URL` | URL do webhook | *obrigatório* |
| `API_USER` | Header `X-API-USER` | *obrigatório* |
| `API_KEY` | Header `X-API-KEY` | *obrigatório* |
| `API_TIMEOUT` | Timeout HTTP (segundos) | `300` |
| `API_VERIFY_SSL` | Validar cadeia TLS do servidor da API | `true` |
| `API_RETRY_TOTAL` | Tentativas em falhas transientes (reset, 5xx) | `3` |
| `API_RETRY_BACKOFF` | Fator de backoff exponencial (1 = 1s, 2s, 4s) | `1` |
| `LOCK_FILE` | Lock contra execução concorrente | `/run/tls-renewer/renewer.lock` |
| `RENEW_DAYS_BEFORE` | Dias antes do vencimento para renovar | `30` |
| `SMTP_HOST` / `PORT` / `USER` / `PASS` | SMTP para notificações | — |
| `EMAIL_FROM` / `EMAIL_TO` | Remetente / destinatários (separados por vírgula) | — |

---

## Uso

### Execução agendada (systemd timer)

```bash
sudo systemctl enable --now tls-renewer.timer
sudo systemctl list-timers tls-renewer.timer
```

O timer padrão executa diariamente às 06:00 (horário local) com até 15 minutos de jitter. Para executar exatamente às 06:00:

```bash
sudo sed -i 's/^RandomizedDelaySec=.*/RandomizedDelaySec=0/' /etc/systemd/system/tls-renewer.timer
sudo systemctl daemon-reload
sudo systemctl restart tls-renewer.timer
```

### Manual (CLI)

```bash
tls-renew                                  # Normal: só renova certs próximos do vencimento
tls-renew --force                          # Força renovação de TODOS os CSRs
tls-renew --domain exemplo.com             # Processa apenas 1 domínio
tls-renew --domain exemplo.com --force     # Força 1 domínio
```

### Logs

```bash
journalctl -u tls-renewer.service --since today
tail -f /var/log/tls-renewer/tls-renewer.log
```

---

## Como funciona a extração da cadeia

Espera-se que a resposta da API inclua:

- `certificado_pem_individual` — certificado leaf emitido
- `certificado_cadeia_pkcs7` — cadeia completa em formato PKCS7

A função `extract_chain_from_pkcs7()` analisa o PKCS7 e classifica cada certificado:

- **Root CA**: self-signed (`issuer == subject`) → salvo em `chain/root.pem`
- **Intermediate**: não-self-signed, CN contém `"CA"` → salvo em `chain/intermediate.pem`
- **Leaf**: ignorado aqui (já obtido via `certificado_pem_individual`)

Os arquivos da cadeia só são reescritos quando o conteúdo muda, então timestamps permanecem estáveis entre execuções que não alteraram a cadeia.

### Adaptando para um formato diferente de resposta da API

Se sua API usa chaves JSON diferentes, edite `extract_cert_from_response()` em `tls_renewer.py`. A função tem lógica de fallback que procura por chaves comuns: `certificate`, `cert`, `crt`, `pem`, `data`, `result`.

---

## Troubleshooting

### `OSError: [Errno 30] Read-only file system` ao gravar em `chain/`

A unit do systemd usa `ProtectSystem=strict`. Garanta que `ReadWritePaths` inclui o diretório da cadeia:

```
ReadWritePaths=/opt/tls-renewer/certs /opt/tls-renewer/chain /var/log/tls-renewer
```

### `No such file or directory: /opt/tls-renewer/venv/bin/python3`

Se o venv foi criado com Python do pyenv (em `/root/.pyenv/`), o `ProtectHome=yes` do systemd vai escondê-lo. Defina `ProtectHome=no` na unit (padrão deste projeto).

### API retorna HTTP 200 com corpo vazio

A API aceitou a requisição silenciosamente mas não retornou nada. Causas comuns:
- API key inválida (algumas APIs retornam 200 em vez de 401 quando auth falha)
- IP não liberado no firewall do servidor da API

Diagnostique com cURL:

```bash
jq -Rs '{csr: .}' /opt/tls-renewer/csr/qualquer.csr | \
  curl -ks -D- -X POST "$API_URL" \
    -H "X-API-USER: $API_USER" -H "X-API-KEY: $API_KEY" \
    -H "Content-Type: application/json" -d @-
```

### E-mail de notificação não chega

O servidor SMTP pode rejeitar silenciosamente mensagens com `EMAIL_FROM` não autorizado. Use um endereço que esteja efetivamente autorizado a enviar pelo seu relay SMTP.

---

## Segurança

- `.env` deve ter permissão `600`, owner root.
- Nunca commite o `.env` (já está no `.gitignore`).
- A unit do systemd aplica hardening: `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`.
- Credenciais da API nunca aparecem em logs (apenas categorias de erro).

---

## Projeto companheiro

[**TLS-Distributor**](https://github.com/wgfreitas/tls-distributor) — distribui certificados produzidos por esta ferramenta para servidores web remotos via SSH/SFTP, faz backups, aplica ownership e dispara reloads.

---

## Origem

Desenvolvido originalmente no SINFO/IRR/Fiocruz (Instituto René Rachou, Brasil) para automatizar a renovação de TLS em uma infraestrutura interna de ~65 servidores web usando uma CA organizacional baseada em webhook. Generalizado e disponibilizado como código aberto sob MIT.

---

## Licença

MIT — veja [LICENSE](LICENSE).
