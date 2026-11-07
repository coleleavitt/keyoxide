use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Run { replace: bool },
    Check,
    Passwd,
    Help,
    Version,
}

pub const HELP: &str = "\
keyoxide - no-prompt SSH and GPG agent

Usage:
  keyoxide [--replace]
  keyoxide --check
  keyoxide passwd
  keyoxide --help
  keyoxide --version

Options:
  --replace      Stop the native gpg-agent before starting Keyoxide
  --check        Exit successfully only when both Keyoxide sockets respond
  passwd         Re-encrypt every key under a new passphrase and update
                 ~/.config/keyoxide/passphrase (asks twice; reads one line
                 from stdin when it is not a terminal)
  -h, --help     Print this help
  -V, --version  Print the version
";

pub fn parse_args<I>(args: I) -> std::result::Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(Command::Run { replace: false }),
        [arg] if arg == "--replace" => Ok(Command::Run { replace: true }),
        [arg] if arg == "--check" => Ok(Command::Check),
        [arg] if arg == "passwd" => Ok(Command::Passwd),
        [arg] if arg == "-h" || arg == "--help" => Ok(Command::Help),
        [arg] if arg == "-V" || arg == "--version" => Ok(Command::Version),
        [arg] => Err(format!("unknown option: {}", arg.to_string_lossy())),
        _ => Err("options cannot be combined".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> std::result::Result<Command, String> {
        parse_args(args.iter().map(OsString::from))
    }

    #[test]
    fn parses_supported_commands() {
        assert_eq!(parse(&[]), Ok(Command::Run { replace: false }));
        assert_eq!(parse(&["--replace"]), Ok(Command::Run { replace: true }));
        assert_eq!(parse(&["--check"]), Ok(Command::Check));
        assert_eq!(parse(&["passwd"]), Ok(Command::Passwd));
        assert_eq!(parse(&["--help"]), Ok(Command::Help));
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
    }

    #[test]
    fn rejects_unknown_or_combined_options() {
        assert!(parse(&["--wat"]).is_err());
        assert!(parse(&["--check", "--replace"]).is_err());
    }
}
