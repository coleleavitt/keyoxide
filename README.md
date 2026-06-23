# keyoxide

A minimal, no-prompt SSH and GPG agent. It loads your existing OpenSSH and
GnuPG private keys at startup (decrypting them once with a configured
passphrase) and serves signing requests over the standard SSH-agent and
gpg-agent sockets — without ever prompting interactively.

> **Security note:** keyoxide holds decrypted private keys in memory and signs
> for any client that can reach its sockets. Run it only on a trusted machine
> and keep `$XDG_RUNTIME_DIR` / `~/.gnupg` at `0700`.

## Configuration

The passphrase used to decrypt your keys is read from, in order:

1. the `KEYOXIDE_PASSPHRASE` environment variable, or
2. `~/.config/keyoxide/passphrase` (a single line, mode `0600`).

Keys are loaded from `~/.ssh` (SSH) and `~/.gnupg/private-keys-v1.d` (GPG).

## Build & run

```sh
cargo build --release
KEYOXIDE_PASSPHRASE=… ./target/release/keyoxide
```

The agent prints the `SSH_AUTH_SOCK` / `GPG_AGENT_INFO` exports to wire up your
shell.

## Supported keys

- **SSH:** RSA (sha2-256/512), Ed25519, ECDSA P-256/P-384 (raw `r‖s` encoding).
- **GPG:** RSA, Ed25519 (eddsa), ECDSA P-256/P-384 — signatures returned as the
  correctly-tagged `sig-val` S-expression.

## Tests

```sh
cargo test
```

## Examples

The `examples/` programs are debugging aids that read real keys from
`~/.gnupg`. They take the passphrase from `KEYOXIDE_PASSPHRASE`:

```sh
KEYOXIDE_PASSPHRASE=… cargo run --example test_load
```

## License

MIT
