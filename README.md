# keyoxide

A minimal, no-prompt SSH and GPG agent. It loads your existing OpenSSH and
GnuPG private keys at startup (decrypting them once with a configured
passphrase) and serves signing requests over the standard SSH-agent and
gpg-agent sockets without prompting interactively.

> **Security note:** keyoxide holds decrypted private keys in memory and signs
> for any client that can reach its sockets. Run it only on a trusted machine
> and keep `$XDG_RUNTIME_DIR` / `~/.gnupg` at `0700`.

## Configuration

The passphrase used to decrypt your keys is read from, in order:

1. the `KEYOXIDE_PASSPHRASE` environment variable, or
2. `~/.config/keyoxide/passphrase` (a single line, owned by the current user
   and inaccessible to group/others).

Keys are loaded from `~/.ssh` (SSH) and `~/.gnupg/private-keys-v1.d` (GPG).
Key files protected by a different passphrase are skipped with a warning.

## Build & run

```sh
cargo build --release
./target/release/keyoxide --replace
```

`--replace` explicitly stops the native `gpg-agent` before Keyoxide binds the
canonical GPG socket. Without that flag, Keyoxide refuses to unlink any live
socket. Stale sockets are reclaimed safely, and partial startup is rolled back.

The agent prints the `SSH_AUTH_SOCK` export for your shell. Modern GnuPG ignores
`GPG_AGENT_INFO`, so GPG requests reach Keyoxide only while it owns the socket
reported by `gpgconf --list-dirs agent-socket`.

Check both protocols without loading private keys or creating sockets:

```sh
keyoxide --check
```

`--help` and `--version` are also available. Unknown or combined options fail
instead of starting the daemon.

## OpenRC user service

On an OpenRC system with user services enabled, install and supervise Keyoxide
without root:

```sh
cargo install --path .
install -Dm755 contrib/openrc/keyoxide ~/.config/rc/init.d/keyoxide
rc-update --user add keyoxide default
rc-service --user keyoxide start
keyoxide --check
```

Logs are written under `${XDG_STATE_HOME:-~/.local/state}/keyoxide/`. Remove any
shell-startup snippet that launches Keyoxide directly after enabling the
service; OpenRC handles startup, cleanup, and crash restarts, while
`keyoxide --check` reports protocol health. Shells still need the export itself
(but must not launch the daemon):

```sh
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/keyoxide/ssh.sock"
```

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
