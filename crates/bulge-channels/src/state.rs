//! What channels remember across restarts: each app's poll cursor (so no
//! message is handled twice or lost) and which bulge conversation each chat
//! continues.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct Data {
    /// channel name → opaque cursor (Telegram update offset, Matrix since token, …).
    #[serde(default)]
    cursors: BTreeMap<String, String>,
    /// chat key (`channel:chat`) → bulge job id of its conversation.
    #[serde(default)]
    conversations: BTreeMap<String, String>,
}

pub struct ChannelState {
    path: PathBuf,
    data: Data,
}

impl ChannelState {
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        Ok(Self { path: path.to_path_buf(), data })
    }

    fn save(&self) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(&self.data).map_err(|e| e.to_string())?;
        crate::access::write_atomic(&self.path, &json)
    }

    pub fn cursor(&self, channel: &str) -> Option<&str> {
        self.data.cursors.get(channel).map(String::as_str)
    }

    pub fn set_cursor(&mut self, channel: &str, cursor: &str) -> Result<(), String> {
        self.data.cursors.insert(channel.to_owned(), cursor.to_owned());
        self.save()
    }

    pub fn conversation(&self, chat_key: &str) -> Option<&str> {
        self.data.conversations.get(chat_key).map(String::as_str)
    }

    pub fn set_conversation(&mut self, chat_key: &str, job_id: &str) -> Result<(), String> {
        self.data.conversations.insert(chat_key.to_owned(), job_id.to_owned());
        self.save()
    }

    /// Start the chat's next message in a new conversation.
    pub fn forget_conversation(&mut self, chat_key: &str) -> Result<(), String> {
        self.data.conversations.remove(chat_key);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_and_conversations_persist() {
        let path = std::env::temp_dir().join(format!("bulge-chstate-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut state = ChannelState::load(&path).unwrap();
        state.set_cursor("telegram:main", "42").unwrap();
        state.set_conversation("telegram:main:7", "j-1").unwrap();
        let state = ChannelState::load(&path).unwrap();
        assert_eq!(state.cursor("telegram:main"), Some("42"));
        assert_eq!(state.conversation("telegram:main:7"), Some("j-1"));
    }
}
