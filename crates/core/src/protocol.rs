use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{fail, Result};

pub const VERSION: u16 = 1;
pub const MAX_TEXT: usize = 16 * 1024;
pub const MAX_FRAME: usize = 60 * 1024;
pub const MAX_QUEUE: usize = 32;
pub const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode { AppleLocal, DoubaoIme }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ack { Received, Applied, NotApplied, Unknown }
impl Ack {
    pub fn as_str(self) -> &'static str {
        match self { Self::Received => "received", Self::Applied => "applied", Self::NotApplied => "not_applied", Self::Unknown => "unknown" }
    }
    pub fn parse(s: &str) -> Self {
        match s { "applied" => Self::Applied, "not_applied" => Self::NotApplied, "received" => Self::Received, _ => Self::Unknown }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase { Preparing, Ready, Listening, Finalizing, AwaitingConfirmation, Committing, Paused, Unknown, Done, Cancelled, StopFailed }
impl Phase {
    pub fn terminal(self) -> bool { matches!(self, Self::Done | Self::Cancelled) }
    pub fn accepts_text(self) -> bool { matches!(self, Self::Listening | Self::Finalizing) }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub session_id: Uuid,
    pub source_device_id: String,
    pub target_device_id: String,
    pub controller_device_id: String,
    pub input_mode: Mode,
    pub context_token: String,
    pub target_app: String,
    pub created_ms: u64,
}
impl Binding {
    pub fn validate(&self, now: u64) -> Result<()> {
        if self.session_id.is_nil() || !valid_id(&self.source_device_id) || !valid_id(&self.target_device_id)
            || !valid_id(&self.controller_device_id) || self.target_app.len() > 256
            || self.context_token.len() > 128 || now.abs_diff(self.created_ms) > 60_000 {
            return fail("invalid_binding");
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wire {
    pub protocol_version: u16,
    pub request_id: Uuid,
    pub payload: Payload,
}
impl Wire {
    pub fn new(payload: Payload) -> Self { Self { protocol_version: VERSION, request_id: Uuid::new_v4(), payload } }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FRAME - 32 { return fail("message_too_large"); }
        let wire: Self = serde_json::from_slice(bytes).map_err(|_| crate::err("invalid_message"))?;
        if wire.protocol_version != VERSION || wire.request_id.is_nil() { return fail("protocol_version"); }
        Ok(wire)
    }
}

// This is the entire network allowlist. No audio, keyboard, command or script payload exists.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Hello { device_id: String, name: String },
    PairConfirm,
    BindRequest { binding: Binding },
    SessionBound { binding: Binding },
    SessionStart { binding: Binding },
    SessionReady { session_id: Uuid },
    SessionState { session_id: Uuid, phase: Phase },
    SessionKeepalive { session_id: Uuid },
    SessionStop { session_id: Uuid },
    SessionCancel { session_id: Uuid },
    TextChunk { session_id: Uuid, sequence: u64, context_token: String, text: String, is_final: bool },
    ChunkAck { session_id: Uuid, sequence: u64, ack_status: Ack },
    ChunkQuery { session_id: Uuid, sequence: u64 },
    SessionEnd { session_id: Uuid, last_sequence: u64 },
    SessionPause { session_id: Uuid },
    SessionResume { session_id: Uuid, context_token: String, target_app: String },
    Error { session_id: Option<Uuid>, code: String },
}

pub fn valid_id(id: &str) -> bool { id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) }
pub fn validate_text(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_TEXT { return fail("invalid_text_length"); }
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') { return fail("unsafe_control_character"); }
    Ok(())
}
