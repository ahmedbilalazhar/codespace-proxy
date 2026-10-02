# Changelog

## 0.11.3

- Bypass VS Code's HTTP proxy overrides during direct public-IP discovery so
  Wi-Fi repair does not authorize the proxy server's IP instead of the laptop.
- Retain HTTPS certificate validation and bounded networking timeouts.
- Strip inherited proxy settings from AWS CLI repair subprocesses so security
  group updates can run while the localhost proxy is down.
- Verify automatic startup recovery before the failure threshold, healthy
  startup without unnecessary restarts, and persistent Proxy Off behavior.
- Document one-time SSH host trust and automatic startup/roaming settings.

## 0.11.2

- Finish framed HTTP/SOCKS responses and bodyless HTTPS probes as soon as they
  are complete; persistent connections no longer cause false timeouts.
- Preserve partial-response and malformed-framing failures, including truncated
  TLS responses and invalid chunk terminators.
- Reject Windows command expansion in AWS CLI settings.
- Include the installable VSIX and document version verification and packaging.
- Carry forward the SSH startup diagnostics, roaming recovery fixes, and safe
  proxy shutdown from the preceding update.

## 0.11.1

- Capture bounded, redacted SSH/bridge startup output and process exit status.
- Explain host trust, authentication, key-file, and port-conflict failures.
- Serialize automatic Wi-Fi checks and release stuck reconnection states.
- Verify new security-group access before pruning stale managed rules.
- Decode chunked HTTP responses and preserve UTF-8 across TCP packets.
- Preserve CONNECT rejection statuses and support informational responses.

## 0.11.0

- Add persistent Turn Proxy Off/On commands with verified shutdown.
- Fix recovery deadlocks, retry cooldowns, stale process replacement,
  SOCKS handshake parsing, and Windows batch launch behavior.
