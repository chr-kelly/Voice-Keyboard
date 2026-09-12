mod engine;
mod journal;
mod protocol;
mod stable;
mod transport;

use std::sync::{Arc, Mutex};
use serde_json::Value;
uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{code}")]
    Failure { code: String },
}
pub type Result<T> = std::result::Result<T, CoreError>;
pub(crate) fn err(code: &str) -> CoreError { CoreError::Failure { code: code.into() } }
pub(crate) fn fail<T>(code: &str) -> Result<T> { Err(err(code)) }

#[uniffi::export]
pub fn generate_identity() -> Result<String> {
    serde_json::to_string(&transport::Identity::generate()?).map_err(|_| err("serialization_error"))
}

// One coarse-grained JSON command/event boundary; audio never crosses this boundary.
// The mutex serializes socket, timer, hotkey, and injection completions.
#[derive(uniffi::Object)]
pub struct Core { engine: Mutex<engine::Engine> }
#[uniffi::export]
impl Core {
    #[uniffi::constructor]
    pub fn new(config_json: String) -> Result<Arc<Self>> {
        let config = serde_json::from_str(&config_json).map_err(|_| err("invalid_configuration"))?;
        Ok(Arc::new(Self { engine: Mutex::new(engine::Engine::new(config)?) }))
    }
    pub fn device_id(&self) -> Result<String> {
        Ok(self.engine.lock().map_err(|_| err("core_unavailable"))?.id.clone())
    }
    pub fn dispatch(&self, command_json: String) -> Result<String> {
        if command_json.len() > 200_000 { return fail("command_limit"); }
        let command: Value = serde_json::from_str(&command_json).map_err(|_| err("invalid_command"))?;
        let mut core = self.engine.lock().map_err(|_| err("core_unavailable"))?;
        let result = core.command(command);
        core.enforce_event_limit();
        serde_json::to_string(&result?).map_err(|_| err("serialization_error"))
    }
    pub fn poll_events(&self) -> Result<Vec<String>> {
        let mut core = self.engine.lock().map_err(|_| err("core_unavailable"))?;
        core.enforce_event_limit();
        core.events.drain(..).map(|v| serde_json::to_string(&v).map_err(|_| err("serialization_error"))).collect()
    }
}
