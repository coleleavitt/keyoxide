use std::path::Path;

use keyoxide::gpg::keys::load_gpg_keys;

fn main() {
    tracing_subscriber::fmt().with_env_filter("debug").init();

    let gpg_dir = Path::new("/home/cole/.gnupg/private-keys-v1.d");
    let passphrase =
        std::env::var("KEYOXIDE_PASSPHRASE").expect("set KEYOXIDE_PASSPHRASE to run this example");

    println!("Loading GPG keys from {:?}", gpg_dir);
    let keys = load_gpg_keys(gpg_dir, &passphrase);
    println!("Loaded {} keys", keys.len());

    for key in &keys {
        println!("  - {}", key.keygrip);
    }
}
