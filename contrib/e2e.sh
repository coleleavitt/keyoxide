#!/bin/bash
# End-to-end check of keyoxide against real GnuPG and OpenSSH, fully
# isolated: a throwaway HOME and GNUPGHOME, its own sockets, and no pinentry.
# It never touches your keyring or the agent you are running.
#
#   cargo build --release && contrib/e2e.sh
#
# Test keys are generated once into KX_FIXTURE (default ~/.cache/keyoxide-e2e)
# by the real gpg-agent; delete that directory to regenerate them.
set -u
KX_BIN=${KX_BIN:-$(dirname "$0")/../target/release/keyoxide}
KX_BIN=$(realpath "$KX_BIN")
FIX=${KX_FIXTURE:-${XDG_CACHE_HOME:-$HOME/.cache}/keyoxide-e2e}
REAL_SOCK=$(env -u GNUPGHOME gpgconf --list-dirs agent-socket)
R=$(mktemp -d -t kx-e2e.XXXX); chmod 700 "$R"
# GNUPGHOME must not be $HOME/.gnupg: GnuPG treats that as the default home
# and would talk to the real agent socket.
# Socket paths must fit in sun_path (108 bytes), so runtime files live under /run/user.
export HOME=$R/home GNUPGHOME=$R/gnupg XDG_RUNTIME_DIR=$(mktemp -d -p /run/user/$(id -u) kxe.XXXX)
mkdir -p -m 700 "$HOME" "$GNUPGHOME" "$XDG_RUNTIME_DIR"
unset DISPLAY WAYLAND_DISPLAY GPG_TTY
# No pinentry may ever open: loopback or keyoxide supply every passphrase.
printf 'pinentry-program /bin/false\nallow-loopback-pinentry\n' > "$GNUPGHOME/gpg-agent.conf"
gpg() { timeout 30 /usr/bin/gpg "$@"; }
PASS=test-pass
G="gpg --batch --pinentry-mode loopback --passphrase $PASS"
fpr() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'; }
cleanup() { [ -n "${KXPID:-}" ] && kill "$KXPID" 2>/dev/null; gpgconf --kill gpg-agent 2>/dev/null; rm -rf "$R" "$XDG_RUNTIME_DIR"; }
trap cleanup EXIT

if [ ! -f "$FIX/done" ]; then
  [ "$(gpgconf --list-dirs agent-socket)" = "$REAL_SOCK" ] && { echo "REFUSING: test home maps to the real agent socket"; exit 1; }
  # Keys made by the real gpg-agent, protected with $PASS
  $G --quick-gen-key 'Ed <ed@test.invalid>' ed25519 sign never; ED=$(fpr ed@test.invalid)
  $G --quick-add-key "$ED" cv25519 encr never
  $G --quick-gen-key 'Rsa <rsa@test.invalid>' rsa2048 sign never; RSA=$(fpr rsa@test.invalid)
  $G --quick-add-key "$RSA" rsa2048 encr never
  $G --quick-gen-key 'P256 <p@test.invalid>' nistp256 sign never; P=$(fpr p@test.invalid)
  $G --quick-add-key "$P" nistp256 encr never
  # Keys to import later: same passphrase, another passphrase, unprotected
  for who in imp other bare; do
    case $who in imp) pp=$PASS;; other) pp=other-pass;; bare) pp='';; esac
    gpg --batch --pinentry-mode loopback --passphrase "$pp" --quick-gen-key "Imp <$who@test.invalid>" ed25519 sign never
    F=$(fpr $who@test.invalid)
    gpg --batch --pinentry-mode loopback --passphrase "$pp" --quick-add-key "$F" cv25519 encr never
    gpg --batch --pinentry-mode loopback --passphrase "$pp" --export-secret-keys "$F" > "$R/$who.sec"
    gpg --batch --yes --delete-secret-and-public-keys "$F"
  done
  echo hello > "$R/msg"
  for k in "$ED" "$RSA" "$P"; do gpg --batch --yes --trust-model always -r "$k" -o "$R/$k.gpg" -e "$R/msg"; done
  gpgconf --kill gpg-agent
  rm -rf "$FIX"; mkdir -p "$FIX"; cp -a "$GNUPGHOME" "$FIX/gnupg"; cp "$R"/*.sec "$R"/*.gpg "$R/msg" "$FIX/"
  echo "$ED $RSA $P" > "$FIX/fprs"; touch "$FIX/done"
fi
rm -rf "$GNUPGHOME"; cp -a "$FIX/gnupg" "$GNUPGHOME"; cp "$FIX"/*.sec "$FIX"/*.gpg "$FIX/msg" "$R/"
read ED RSA P < "$FIX/fprs"
echo "keys: $(gpg -K --with-colons | grep -c ^sec) sec, $(ls $GNUPGHOME/private-keys-v1.d | wc -l) key files"

mkdir -p -m 700 "$HOME/.ssh" "$HOME/.config/keyoxide"
ssh-keygen -q -t ed25519 -N "$PASS" -C e2e@test.invalid -f "$HOME/.ssh/id_ed25519"
ssh-keygen -q -t rsa -b 2048 -N "$PASS" -C e2e-rsa@test.invalid -f "$HOME/.ssh/id_rsa"
printf '%s\n' "$PASS" > "$HOME/.config/keyoxide/passphrase"; chmod 600 "$HOME/.config/keyoxide/passphrase"
# A key under another passphrase, made by the real agent: keyoxide skips it
# at startup until `gpg --passwd` brings it in.
gpg --batch --pinentry-mode loopback --passphrase foreign-pass --quick-gen-key 'Foreign <foreign@test.invalid>' ed25519 sign never 2>/dev/null

# Swap in keyoxide (it reads the passphrase file, like the real service)
start_keyoxide() {
  : > "$R/kx.log"
  RUST_LOG=keyoxide=${KX_LOG:-info} "$KX_BIN" --replace >"$R/kx.log" 2>&1 &
  KXPID=$!
  for i in $(seq 1 40); do grep -q 'GPG agent listening' "$R/kx.log" && break; sleep 0.1; done
  greet=$(timeout 3 socat - UNIX-CONNECT:"$(gpgconf --list-dirs agent-socket)" </dev/null 2>/dev/null | head -1)
  case "$greet" in *keyoxide*) ;; *) echo "ABORT: keyoxide did not take the socket (greeting: $greet)"; sed 's/\x1b\[[0-9;]*m//g' "$R/kx.log" | tail -15; exit 1;; esac
  grep -E 'loaded [0-9]+ (GPG|SSH)' "$R/kx.log" | sed 's/\x1b\[[0-9;]*m//g; s/.*keyoxide[^ ]*: //' | tr '\n' ' '; echo
}
start_keyoxide

FAILS=0
check() { local name=$1; shift; if out=$("$@" 2>&1); then echo "PASS $name"; else echo "FAIL $name :: $(echo "$out" | tail -1)"; FAILS=$((FAILS + 1)); fi; }
for k in ED RSA P; do f=${!k}; check "sign-$k" bash -c "gpg --batch --yes -u $f -o $R/s.sig --detach-sign $R/msg && gpg --verify $R/s.sig $R/msg"; done
for k in ED RSA P; do f=${!k}; check "decrypt-$k" bash -c "gpg --batch -d $R/$f.gpg | grep -qx hello"; done
check "import-same-pass" bash -c "gpg --batch --import $R/imp.sec && gpg --batch --yes -u imp@test.invalid -o $R/i.sig --detach-sign $R/msg"
check "import-unprotected" bash -c "gpg --batch --import $R/bare.sec && gpg --batch --yes -u bare@test.invalid -o $R/b.sig --detach-sign $R/msg"
check "import-other-pass-loopback" bash -c "gpg --batch --pinentry-mode loopback --passphrase other-pass --import $R/other.sec && gpg --batch --yes -u other@test.invalid -o $R/o.sig --detach-sign $R/msg"
check "imported-listed-as-secret" bash -c "for w in imp other bare; do gpg -K --with-colons \$w@test.invalid | grep -q '^ssb:.*:+:' || exit 1; done"
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keyoxide/ssh.sock
check "ssh-extension-keeps-connection" python3 -c '
import socket, struct, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.settimeout(3)
def send(t, p=b""):
    s.sendall(struct.pack(">I", 1 + len(p)) + bytes([t]) + p)
    n = struct.unpack(">I", s.recv(4))[0]; return s.recv(n)[0]
name = b"session-bind@openssh.com"
assert send(27, struct.pack(">I", len(name)) + name) == 5, "expected SSH_AGENT_FAILURE"
assert send(11) == 12, "expected IDENTITIES_ANSWER on the same connection"
' "$SSH_AUTH_SOCK"
check "ssh-add-lists-key" bash -c "ssh-add -l | grep -q e2e@test.invalid"
check "ssh-agent-signs" bash -c "echo data > $R/d && ssh-keygen -q -Y sign -n file -f $HOME/.ssh/id_ed25519.pub $R/d && ssh-keygen -q -Y check-novalidate -n file -f $HOME/.ssh/id_ed25519.pub -s $R/d.sig < $R/d"
check "ssh-add-reports-unsupported" bash -c "! ssh-add -D 2>/dev/null"
# GENKEY: gpg generates keys through keyoxide; they work at once.
check "genkey-quick-gen-and-add" bash -c "gpg --batch --quick-gen-key 'Gen <gen@test.invalid>' ed25519 sign never \
  && F=\$(gpg --list-keys --with-colons gen@test.invalid | awk -F: '/^fpr/{print \$10; exit}') \
  && gpg --batch --quick-add-key \$F rsa2048 encr never && gpg --batch --quick-add-key \$F nistp256 sign never \
  && gpg --batch --quick-add-key \$F cv25519 encr never"
check "genkey-sign-and-decrypt" bash -c "gpg --batch --yes -u gen@test.invalid -o $R/g1.sig --detach-sign $R/msg \
  && gpg --verify $R/g1.sig $R/msg && gpg --batch --yes --trust-model always -r gen@test.invalid -o $R/g.gpg -e $R/msg \
  && gpg --batch -d $R/g.gpg | grep -qx hello"
check "genkey-keys-listed-as-secret" bash -c "[ \$(gpg -K --with-colons gen@test.invalid | grep -cE '^(sec|ssb):u:.*:\+:') -eq 4 ]"

# PASSWD: keyoxide keys re-protect in place; a foreign key comes in with loopback.
check "passwd-own-key" bash -c "gpg --batch --passwd gen@test.invalid && gpg --batch --yes -u gen@test.invalid -o $R/g2.sig --detach-sign $R/msg"
check "foreign-key-skipped-until-passwd" bash -c "! gpg --batch --yes -u foreign@test.invalid -o $R/f.sig --detach-sign $R/msg 2>/dev/null"
check "passwd-brings-foreign-key-in" bash -c "gpg --batch --pinentry-mode loopback --passphrase foreign-pass --passwd foreign@test.invalid \
  && gpg --batch --yes -u foreign@test.invalid -o $R/f.sig --detach-sign $R/msg"

# EXPORT_KEY: the export imports into a separate home run by the real gpg-agent.
check "export-secret-keys-roundtrip" bash -c "gpg --batch --armor --export-secret-keys $ED > $R/exp.asc && grep -q 'PRIVATE KEY BLOCK' $R/exp.asc \
  && export GNUPGHOME=$R/gnupg2 && mkdir -m 700 \$GNUPGHOME && printf 'pinentry-program /bin/false\nallow-loopback-pinentry\n' > \$GNUPGHOME/gpg-agent.conf \
  && gpg --batch --pinentry-mode loopback --passphrase $PASS --import $R/exp.asc \
  && gpg --batch --pinentry-mode loopback --passphrase $PASS --yes -u $ED -o $R/x.sig --detach-sign $R/msg && gpg --verify $R/x.sig $R/msg \
  && gpg --batch --pinentry-mode loopback --passphrase $PASS -d $R/$ED.gpg | grep -qx hello; rc=\$?; gpgconf --kill gpg-agent; exit \$rc"

# ssh-rsa: no SHA-2 flag means a SHA-1 PKCS#1 signature named "ssh-rsa".
check "ssh-rsa-sha1-signature" python3 -c '
import socket, struct, subprocess, sys
sock, pub, out = sys.argv[1:4]
s = socket.socket(socket.AF_UNIX); s.connect(sock); s.settimeout(5)
def call(t, p=b""):
    s.sendall(struct.pack(">I", 1 + len(p)) + bytes([t]) + p)
    n = struct.unpack(">I", s.recv(4))[0]; data = b""
    while len(data) < n: data += s.recv(n - len(data))
    return data
def string(b, o): n = struct.unpack(">I", b[o:o+4])[0]; return b[o+4:o+4+n], o + 4 + n
blob = __import__("base64").b64decode(open(pub).read().split()[1])
data = b"keyoxide ssh-rsa check"
r = call(13, struct.pack(">I", len(blob)) + blob + struct.pack(">I", len(data)) + data + struct.pack(">I", 0))
assert r[0] == 14, r[:1]
sig, _ = string(r, 1); alg, o = string(sig, 0); raw, _ = string(sig, o)
assert alg == b"ssh-rsa", alg
open(out + ".data", "wb").write(data); open(out + ".sig", "wb").write(raw)
' "$SSH_AUTH_SOCK" "$HOME/.ssh/id_rsa.pub" "$R/rsa" && ssh-keygen -e -m PKCS8 -f "$HOME/.ssh/id_rsa.pub" > "$R/rsa.pem" \
  && openssl dgst -sha1 -verify "$R/rsa.pem" -signature "$R/rsa.sig" "$R/rsa.data" >/dev/null

check "keyfiles-readable-by-gnupg" bash -c "kill $KXPID; sleep 0.3; KXPID=; gpg --batch --pinentry-mode loopback --passphrase $PASS -u imp@test.invalid -o $R/g.sig --yes --detach-sign $R/msg"
[ -n "${KX_SHOWLOG:-}" ] && sed 's/\x1b\[[0-9;]*m//g' "$R/kx.log" | grep -E 'GPG <-|GPG ->' | cut -c1-200
# keyoxide passwd: every key moves to a new passphrase; keyoxide restarts with it.
NEW=new-pass
check "keyoxide-passwd" bash -c "echo $NEW | '$KX_BIN' passwd > $R/passwd.out 2>&1 \
  && grep -qx $NEW $HOME/.config/keyoxide/passphrase && ls -d \$HOME/.local/state/keyoxide/passwd-backup-* >/dev/null"
gpgconf --kill gpg-agent; sleep 0.3
start_keyoxide
check "after-passwd-gpg-sign-and-decrypt" bash -c "gpg --batch --yes -u $ED -o $R/n.sig --detach-sign $R/msg && gpg --batch -d $R/$RSA.gpg | grep -qx hello"
check "after-passwd-ssh" bash -c "ssh-add -l | grep -q e2e-rsa@test.invalid && echo d > $R/d2 && ssh-keygen -q -Y sign -n file -f $HOME/.ssh/id_ed25519.pub $R/d2"
check "after-passwd-old-passphrase-rejected" bash -c "! ssh-keygen -y -P $PASS -f $HOME/.ssh/id_ed25519 >/dev/null 2>&1 && ssh-keygen -y -P $NEW -f $HOME/.ssh/id_ed25519 >/dev/null"
[ "$FAILS" -eq 0 ] && echo "all checks passed" || { echo "$FAILS check(s) failed"; exit 1; }
