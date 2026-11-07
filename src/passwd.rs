//! `keyoxide passwd`: move every key keyoxide unlocks to a new passphrase.
//!
//! keyoxide unlocks all SSH and GPG keys with the one passphrase in
//! `~/.config/keyoxide/passphrase`. Changing it means re-encrypting each key
//! under the new passphrase and then updating that file. Nothing on disk
//! changes until every re-encrypted key has been staged and verified; the
//! originals are kept in a backup directory.

use std::io::{BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use ssh_key::{LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::gpg::keyfile;

/// A re-encrypted copy waiting next to the file it will replace.
struct Staged {
    target: PathBuf,
    temp: PathBuf,
    backup_name: PathBuf,
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Removes the temp file unless it was renamed into place.
        let _ = std::fs::remove_file(&self.temp);
    }
}

pub fn run() -> Result<()> {
    if std::env::var_os("KEYOXIDE_PASSPHRASE").is_some() {
        return Err(Error::Config(
            "KEYOXIDE_PASSPHRASE is set; passwd updates the passphrase file, so unset it first"
                .into(),
        ));
    }
    let passphrase_file = Config::passphrase_file()?;
    let config = Config::load()?;
    let old = config.passphrase();

    let new = read_new_passphrase()?;
    if new.is_empty() {
        return Err(Error::Config("the new passphrase is empty".into()));
    }
    if new.as_str() == old {
        return Err(Error::Config(
            "the new passphrase is the same as the old one".into(),
        ));
    }

    let mut staged = Vec::new();
    let mut skipped = Vec::new();
    stage_gpg(&config.gpg_key_dir, old, &new, &mut staged, &mut skipped)?;
    stage_ssh(&config.ssh_key_dir, old, &new, &mut staged, &mut skipped)?;
    if staged.is_empty() {
        return Err(Error::Config(
            "no key opens with the current passphrase; nothing was changed".into(),
        ));
    }

    let backup = backup_dir()?;
    for item in &staged {
        let dest = backup.join(&item.backup_name);
        std::fs::create_dir_all(dest.parent().unwrap_or(&backup))?;
        std::fs::copy(&item.target, &dest)?;
    }
    for item in &staged {
        std::fs::rename(&item.temp, &item.target)?;
    }
    write_private(&passphrase_file, format!("{}\n", new.as_str()).as_bytes())?;

    println!(
        "re-encrypted {} key(s) under the new passphrase:",
        staged.len()
    );
    for item in &staged {
        println!("  {}", item.target.display());
    }
    for (path, why) in &skipped {
        println!("left unchanged: {} ({why})", path.display());
    }
    println!(
        "originals (still under the old passphrase): {}",
        backup.display()
    );
    println!("delete that directory once you have checked everything works.");
    println!("restart keyoxide to use the new passphrase: rc-service --user keyoxide restart");
    Ok(())
}

fn stage_gpg(
    dir: &Path,
    old: &str,
    new: &str,
    staged: &mut Vec<Staged>,
    skipped: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_key = path.extension().is_some_and(|e| e == "key")
            && path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.len() == 40);
        if !is_key {
            continue;
        }
        let bytes = Zeroizing::new(std::fs::read(&path)?);
        if !keyfile::is_protected(&bytes) {
            skipped.push((path, "not passphrase-protected".into()));
            continue;
        }
        let material = match keyfile::parse_key_file(&bytes, old) {
            Ok(m) => m,
            Err(e) => {
                skipped.push((
                    path,
                    format!("does not open with the current passphrase: {e}"),
                ));
                continue;
            }
        };
        let text = keyfile::render_key_file(&keyfile::protect(
            &material,
            new,
            keyfile::DEFAULT_S2K_COUNT,
        )?)?;
        let item = stage(&path, text.as_bytes(), Path::new("gnupg"))?;
        // Verify before anything is committed.
        keyfile::read_key_file(&item.temp, new)?;
        staged.push(item);
    }
    Ok(())
}

fn stage_ssh(
    dir: &Path,
    old: &str,
    new: &str,
    staged: &mut Vec<Staged>,
    skipped: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    for path in crate::ssh::keys::key_candidates(dir) {
        let Ok(text) = std::fs::read_to_string(&path).map(Zeroizing::new) else {
            continue;
        };
        let Ok(key) = PrivateKey::from_openssh(&*text) else {
            continue;
        };
        if !key.is_encrypted() {
            skipped.push((path, "not passphrase-protected".into()));
            continue;
        }
        let Ok(plain) = key.decrypt(old.as_bytes()) else {
            skipped.push((path, "does not open with the current passphrase".into()));
            continue;
        };
        let reencrypted = plain.encrypt(&mut rand::rngs::OsRng, new.as_bytes())?;
        let item = stage(
            &path,
            reencrypted.to_openssh(LineEnding::LF)?.as_bytes(),
            Path::new("ssh"),
        )?;
        let check =
            PrivateKey::from_openssh(&*Zeroizing::new(std::fs::read_to_string(&item.temp)?))?
                .decrypt(new.as_bytes())?;
        if check.public_key() != plain.public_key() {
            return Err(Error::Config(format!(
                "verification failed for {}",
                path.display()
            )));
        }
        staged.push(item);
    }
    Ok(())
}

fn stage(target: &Path, contents: &[u8], backup_subdir: &Path) -> Result<Staged> {
    let name = target.file_name().ok_or(Error::InvalidMessageFormat)?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".keyoxide-passwd-{}", std::process::id()));
    let temp = target.with_file_name(temp_name);
    let item = Staged {
        target: target.to_path_buf(),
        temp,
        backup_name: backup_subdir.join(name),
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&item.temp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(item)
}

fn backup_dir() -> Result<PathBuf> {
    let state = dirs::state_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".local/state")))
        .ok_or_else(|| Error::Config("no state directory".into()))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dir = state
        .join("keyoxide")
        .join(format!("passwd-backup-{stamp}"));
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    Ok(dir)
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let temp = path.with_extension("keyoxide-new");
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(&temp, path)?;
    Ok(())
}

/// Ask twice on the terminal with echo off; read one line when stdin is
/// not a terminal (scripts, tests).
fn read_new_passphrase() -> Result<Zeroizing<String>> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
        return Ok(Zeroizing::new(trimmed));
    }
    let first = prompt_hidden("New keyoxide passphrase: ")?;
    let second = prompt_hidden("Repeat it: ")?;
    if *first != *second {
        return Err(Error::Config("the passphrases do not match".into()));
    }
    Ok(first)
}

fn prompt_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let fd = libc::STDIN_FILENO;
    let mut saved = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut quiet = saved;
    quiet.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    let mut line = Zeroizing::new(String::new());
    let read = std::io::stdin().lock().read_line(&mut line);
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    eprintln!();
    read?;
    Ok(Zeroizing::new(
        line.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

impl Config {
    /// `~/.config/keyoxide/passphrase`, where `keyoxide passwd` writes.
    pub fn passphrase_file() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .ok_or_else(|| Error::Config("no config directory".into()))?
            .join("keyoxide")
            .join("passphrase"))
    }
}
