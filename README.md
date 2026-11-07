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

## What it supports

- **SSH:** RSA (sha2-256/512), Ed25519, ECDSA P-256/P-384. Keys come from
  `~/.ssh` at startup, so `ssh-add` add/remove requests are refused, and
  extension requests such as OpenSSH's `session-bind@openssh.com` get
  `SSH_AGENT_FAILURE` without dropping the connection.
- **GPG keys:** RSA, Ed25519, Curve25519 (cv25519) and NIST P-256/P-384, from
  `$GNUPGHOME/private-keys-v1.d` (the GnuPG home `gpgconf` reports). Both the
  extended (`Key:`) and the older canonical key-file formats are read.
- **Signing:** `PKSIGN` for every key type above.
- **Decryption:** `PKDECRYPT` for RSA, and for ECDH both the classic form and
  GnuPG 2.5's `--kem=PGP`, where the agent runs the RFC 6637 KDF and unwraps
  the session key itself.
- **Importing secret keys:** `gpg --import` works (`KEYWRAP_KEY` +
  `IMPORT_KEY`). The key is protected with keyoxide's passphrase in GnuPG's
  own format, so gpg-agent can read it too. A key under a different
  passphrase imports with `gpg --pinentry-mode loopback --passphrase ...`.
- **Generating keys:** `gpg --gen-key`, `--quick-gen-key` and
  `--quick-add-key` (`GENKEY`) for Ed25519, Curve25519, NIST P-256/P-384 and
  RSA 2048-8192. New keys are protected with keyoxide's passphrase; gpg
  does not ask for one.
- **Exporting secret keys:** `gpg --export-secret-keys` (`EXPORT_KEY
  --openpgp`). The export is protected with keyoxide's passphrase, which you
  need to import it elsewhere.
- **`gpg --passwd`:** every keyoxide key shares its one passphrase, so this
  re-protects a key under it. That also brings in a key that has another
  passphrase: `gpg --pinentry-mode loopback --passphrase OLD --passwd KEY`.
- **SSH `ssh-rsa`:** RSA requests without a SHA-2 flag get the SHA-1
  signature the protocol defines for them.

Not supported: smartcard keys, and `gpg --export-secret-keys
--export-options mode1003`.

## Changing the passphrase

```sh
keyoxide passwd
rc-service --user keyoxide restart
```

`keyoxide passwd` asks for the new passphrase twice (or reads one line from
stdin when it is not a terminal). It re-encrypts every GPG key file and
every encrypted SSH key that the current passphrase opens, checks that each
new copy opens with the new passphrase, and only then replaces the files and
updates `~/.config/keyoxide/passphrase`. Keys under another passphrase, or
with none, are listed and left alone. The originals are kept in
`~/.local/state/keyoxide/passwd-backup-<time>/`; delete that directory once
everything works, since it still opens with the old passphrase. Restart
keyoxide afterwards so it reads the new passphrase.

## Tests

```sh
cargo test
cargo build --release && contrib/e2e.sh
```

`contrib/e2e.sh` drives real GnuPG and OpenSSH against the built binary:
signing, decryption and import for every key type, the SSH agent, and that
gpg-agent can read the key files keyoxide writes. It runs in a throwaway home
with its own sockets and no pinentry, so it never touches your keys or the
running agent.

## Examples

The `examples/` programs are debugging aids that read real keys from
`~/.gnupg`. They take the passphrase from `KEYOXIDE_PASSPHRASE`:

```sh
KEYOXIDE_PASSPHRASE=… cargo run --example test_load
```

## License

MIT
