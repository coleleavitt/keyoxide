use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::config::SocketPaths;
use crate::error::{Error, Result};

const IO_TIMEOUT: Duration = Duration::from_millis(500);

pub fn check_agent(paths: &SocketPaths) -> Result<()> {
    check_ssh(&paths.ssh_socket_path)?;
    if !gpg_is_keyoxide(&paths.gpg_socket_path)? {
        return Err(Error::AgentUnhealthy(format!(
            "{} is not served by Keyoxide",
            paths.gpg_socket_path.display()
        )));
    }
    Ok(())
}

pub fn gpg_is_keyoxide(path: &Path) -> Result<bool> {
    let stream = connect(path)?;
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.by_ref().take(512).read_line(&mut greeting)?;
    Ok(greeting.contains("keyoxide"))
}

fn check_ssh(path: &Path) -> Result<()> {
    let mut stream = connect(path)?;
    stream.write_all(&[0, 0, 0, 1, 11])?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header);
    let mut response = [0u8; 5];
    stream.read_exact(&mut response)?;
    if length < response.len() as u32 || response[0] != 12 {
        return Err(Error::AgentUnhealthy(format!(
            "{} returned an invalid SSH-agent response",
            path.display()
        )));
    }
    Ok(())
}

fn connect(path: &Path) -> Result<UnixStream> {
    let stream = UnixStream::connect(path).map_err(|source| Error::SocketProbe {
        path: path.to_path_buf(),
        source,
    })?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}
