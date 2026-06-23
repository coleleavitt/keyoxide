use parking_lot::RwLock;

use crate::gpg::keys::GpgKey;
use crate::ssh::keys::SshKey;

pub struct AgentState {
    pub ssh_keys: RwLock<Vec<SshKey>>,
    pub gpg_keys: RwLock<Vec<GpgKey>>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            ssh_keys: RwLock::new(Vec::new()),
            gpg_keys: RwLock::new(Vec::new()),
        }
    }

    pub fn set_ssh_keys(&self, keys: Vec<SshKey>) {
        *self.ssh_keys.write() = keys;
    }

    pub fn set_gpg_keys(&self, keys: Vec<GpgKey>) {
        *self.gpg_keys.write() = keys;
    }

    pub fn ssh_key_count(&self) -> usize {
        self.ssh_keys.read().len()
    }

    pub fn gpg_key_count(&self) -> usize {
        self.gpg_keys.read().len()
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new()
    }
}
