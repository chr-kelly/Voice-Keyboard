mod engine;
mod journal;
mod protocol;
mod stable;
mod transport;

use serde_json::Value;
use std::sync::{Arc, Mutex};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{code}")]
    Failure { code: String },
}

pub type Result<T> = std::result::Result<T, CoreError>;

pub(crate) fn err(code: &str) -> CoreError {
    CoreError::Failure { code: code.into() }
}

pub(crate) fn fail<T>(code: &str) -> Result<T> {
    Err(err(code))
}

#[uniffi::export]
pub fn generate_identity() -> Result<String> {
    serde_json::to_string(&transport::Identity::generate()?)
        .map_err(|_| err("serialization_error"))
}

// This command exists only at the local, authorized UI boundary; it is not a
// network message. A user's explicit verification of stopped recording must
// take the SAME transition as a provider's verified-stop event, including the
// state notification to the target. A local-only phase update left the target
// in StopFailed and caused the subsequently confirmed paragraph to be rejected.
fn normalize_local_command(mut command: Value) -> Result<Value> {
    if !command.is_object() {
        return fail("invalid_command");
    }
    if command["op"] == "confirm_stopped" {
        command["op"] = Value::String("source_stopped".into());
        command["verified"] = Value::Bool(true);
    }
    Ok(command)
}

// One coarse-grained JSON command/event boundary; audio never crosses it.
// The mutex serializes socket, timer, hotkey, and injection completions.
#[derive(uniffi::Object)]
pub struct Core {
    engine: Mutex<engine::Engine>,
}

#[uniffi::export]
impl Core {
    #[uniffi::constructor]
    pub fn new(config_json: String) -> Result<Arc<Self>> {
        let config = serde_json::from_str(&config_json)
            .map_err(|_| err("invalid_configuration"))?;
        Ok(Arc::new(Self {
            engine: Mutex::new(engine::Engine::new(config)?),
        }))
    }

    pub fn device_id(&self) -> Result<String> {
        Ok(self.engine.lock().map_err(|_| err("core_unavailable"))?.id.clone())
    }

    pub fn dispatch(&self, command_json: String) -> Result<String> {
        if command_json.len() > 200_000 {
            return fail("command_limit");
        }
        let command: Value = serde_json::from_str(&command_json)
            .map_err(|_| err("invalid_command"))?;
        let command = normalize_local_command(command)?;
        let mut core = self.engine.lock().map_err(|_| err("core_unavailable"))?;
        let result = core.command(command);
        core.enforce_event_limit();
        serde_json::to_string(&result?).map_err(|_| err("serialization_error"))
    }

    pub fn poll_events(&self) -> Result<Vec<String>> {
        let mut core = self.engine.lock().map_err(|_| err("core_unavailable"))?;
        core.enforce_event_limit();
        core.events.drain(..)
            .map(|v| serde_json::to_string(&v).map_err(|_| err("serialization_error")))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicit_stop_confirmation_uses_canonical_transition() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(normalize_local_command(json!({"op":"confirm_stopped","session_id":id})).unwrap(),
            json!({"op":"source_stopped","session_id":id,"verified":true}));
    }

    #[test]
    fn ordinary_commands_cannot_gain_verified_stop_by_normalization() {
        let command = json!({"op":"stop","session_id":"example"});
        assert_eq!(normalize_local_command(command.clone()).unwrap(), command);
        assert!(normalize_local_command(json!([])).is_err());
    }
}
