use std::{collections::{BTreeMap, HashMap, HashSet, VecDeque}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{err, fail, Result, journal::Journal, protocol::*, stable::StableText, transport::{Channel, ChannelEvent, Identity}};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust { pub peer_id: String, pub name: String, pub allow_remote: bool }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    identity: Identity, name: String, journal_path: String,
    #[serde(default)] peers: Vec<Trust>,
    #[serde(default = "default_lease")] lease_ms: u64,
    #[serde(default = "default_finalizing")] finalizing_ms: u64,
    #[serde(default = "default_max_session")] max_session_ms: u64,
}
fn default_lease() -> u64 { 3000 }
fn default_finalizing() -> u64 { 5000 }
fn default_max_session() -> u64 { 120_000 }
fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
fn string(v: &Value, key: &str) -> Result<String> { v[key].as_str().map(str::to_owned).ok_or_else(|| err("invalid_command")) }
fn sid(v: &Value) -> Result<Uuid> { Uuid::parse_str(&string(v, "session_id")?).map_err(|_| err("invalid_session_id")) }
fn number(v: &Value, key: &str) -> Result<u64> { v[key].as_u64().ok_or_else(|| err("invalid_command")) }
fn valid_context(s: &str) -> bool { Uuid::parse_str(s).is_ok_and(|id| !id.is_nil()) }

struct Chunk { text: String, status: Ack, is_final: bool }
struct Session {
    binding: Binding, phase: Phase, chunks: BTreeMap<u64, Chunk>, draft: String, stable: StableText,
    next_send: u64, next_receive: u64, inflight: Option<(u64, bool)>, last_sequence: Option<u64>,
    retry_allowed: HashSet<u64>, started: Instant, lease: Instant, keepalive_sent: Instant,
    finalizing: Option<Instant>, held: bool, stopped: bool, stop_requested: bool, cancelled: bool, frozen: bool,
}
impl Session {
    fn new(binding: Binding) -> Self {
        let now = Instant::now(); Self { binding, phase: Phase::Preparing, chunks: BTreeMap::new(), draft: String::new(), stable: StableText::default(), next_send: 1, next_receive: 1, inflight: None, last_sequence: None, retry_allowed: HashSet::new(), started: now, lease: now, keepalive_sent: now, finalizing: None, held: true, stopped: false, stop_requested: false, cancelled: false, frozen: false }
    }
    fn other(&self, local: &str) -> String {
        if self.binding.source_device_id == local { self.binding.target_device_id.clone() } else { self.binding.source_device_id.clone() }
    }
    fn can_inject(&self) -> bool { !self.cancelled && !matches!(self.phase, Phase::Preparing | Phase::Paused | Phase::Unknown | Phase::Cancelled | Phase::Done | Phase::StopFailed) }
    fn has_unknown(&self) -> bool { self.chunks.values().any(|c| c.status == Ack::Unknown) }
}

pub struct Engine {
    pub id: String, name: String, private: zeroize::Zeroizing<Vec<u8>>, journal: Journal,
    channels: HashMap<String, Channel>, trust: HashMap<String, Trust>, sessions: HashMap<Uuid, Session>,
    active_source: Option<Uuid>, active_target: Option<Uuid>, seen: VecDeque<(String, Uuid, Vec<u8>)>,
    pub events: VecDeque<Value>, faulted: bool, lease: Duration, finalizing: Duration, max_session: Duration, heartbeat: Instant,
}
impl Engine {
    pub fn new(config: Config) -> Result<Self> {
        if config.name.is_empty() || config.name.len() > 128 || !(1500..=15_000).contains(&config.lease_ms)
            || !(1000..=60_000).contains(&config.finalizing_ms) || !(10_000..=600_000).contains(&config.max_session_ms)
            || config.peers.len() > 100 || config.peers.iter().any(|p| !valid_id(&p.peer_id)) { return fail("invalid_configuration"); }
        let id = config.identity.id()?; let private = config.identity.private_bytes()?;
        let journal = Journal::open(&config.journal_path, &private, now_ms())?;
        Ok(Self { id, private, journal, name: config.name, channels: HashMap::new(), trust: config.peers.into_iter().map(|p| (p.peer_id.clone(), p)).collect(), sessions: HashMap::new(), active_source: None, active_target: None, seen: VecDeque::new(), events: VecDeque::new(), faulted: false, lease: Duration::from_millis(config.lease_ms), finalizing: Duration::from_millis(config.finalizing_ms), max_session: Duration::from_millis(config.max_session_ms), heartbeat: Instant::now() })
    }
    fn emit(&mut self, value: Value) {
        if self.events.len() >= 512 { self.faulted = true; } else { self.events.push_back(value); }
    }
    pub fn enforce_event_limit(&mut self) {
        if !self.faulted { return; }
        self.events.clear();
        for id in self.channels.keys() { self.events.push_back(json!({"event":"socket_close","connection_id":id})); }
        self.channels.clear();
        if let Some(id) = self.active_source { self.events.push_back(json!({"event":"cancel_input","session_id":id})); }
        self.events.push_back(json!({"event":"fatal","code":"event_overflow_restart_required"}));
    }
    fn snapshot(&mut self, s: &Session) {
        let chunks: Vec<Value> = s.chunks.iter().map(|(&n,c)| json!({"sequence":n,"text":c.text,"status":c.status})).collect();
        self.emit(json!({"event":"session","binding":s.binding,"phase":s.phase,"draft":s.draft,"chunks":chunks,"stopped":s.stopped,"cancelled":s.cancelled}));
    }
    fn with_session<T>(&mut self, id: Uuid, f: impl FnOnce(&mut Self, &mut Session) -> Result<T>) -> Result<T> {
        let mut s = self.sessions.remove(&id).ok_or_else(|| err("unknown_session"))?;
        let result = f(self, &mut s);
        if s.phase.terminal() {
            if self.active_source == Some(id) && s.stopped { self.active_source = None; }
            if self.active_target == Some(id) && s.inflight.is_none() { self.active_target = None; }
        }
        self.sessions.insert(id, s); result
    }
    fn connection(&self, peer: &str) -> Result<String> {
        self.channels.iter().find(|(_, c)| c.peer.as_deref() == Some(peer)).map(|(id,_)| id.clone()).ok_or_else(|| err("target_offline"))
    }
    fn send_on(&mut self, connection: &str, payload: Payload) -> Result<()> {
        let bytes = serde_json::to_vec(&Wire::new(payload)).map_err(|_| err("serialization_error"))?;
        let data = self.channels.get_mut(connection).ok_or_else(|| err("target_offline"))?.encrypt(&bytes)?;
        self.emit(json!({"event":"socket_send","connection_id":connection,"data":B64.encode(data)})); Ok(())
    }
    fn send(&mut self, peer: &str, payload: Payload) -> Result<()> {
        if !self.trust.contains_key(peer) { return fail("unpaired_device"); }
        let connection = self.connection(peer)?; self.send_on(&connection, payload)
    }
    fn peer_event(&mut self, peer: &str, online: bool) {
        let c = self.channels.values().find(|c| c.peer.as_deref() == Some(peer));
        let name = c.map(|c| c.name.clone()).or_else(|| self.trust.get(peer).map(|p| p.name.clone())).unwrap_or_default();
        self.emit(json!({"event":"peer","peer_id":peer,"name":name,"online":online,"paired":self.trust.contains_key(peer),"allow_remote":self.trust.get(peer).is_some_and(|p| p.allow_remote),"code":c.map(|c| c.code.clone()).unwrap_or_default()}));
    }
    fn save_trust(&mut self) {
        let mut peers: Vec<Trust> = self.trust.values().cloned().collect(); peers.sort_by(|a,b| a.peer_id.cmp(&b.peer_id));
        self.emit(json!({"event":"trust_changed","peers":peers}));
    }
    fn maybe_pair(&mut self, peer: &str) -> Result<()> {
        let connection = self.connection(peer)?; let c = &self.channels[&connection];
        if c.local_confirmed && c.remote_confirmed {
            self.trust.entry(peer.into()).or_insert(Trust { peer_id: peer.into(), name: c.name.clone(), allow_remote: false });
            self.save_trust(); self.peer_event(peer, true);
        }
        Ok(())
    }
    fn channel_events(&mut self, connection: &str, events: Vec<ChannelEvent>) -> Result<()> {
        for event in events {
            match event {
                ChannelEvent::Write(data) => self.emit(json!({"event":"socket_send","connection_id":connection,"data":B64.encode(data)})),
                ChannelEvent::Authenticated { peer, code } => {
                    if peer == self.id || self.channels.iter().any(|(id,c)| id != connection && c.peer.as_deref() == Some(&peer)) { return fail("duplicate_connection"); }
                    self.send_on(connection, Payload::Hello { device_id: self.id.clone(), name: self.name.clone() })?;
                    self.emit(json!({"event":"secure_channel","peer_id":peer,"code":code}));
                }
                ChannelEvent::Plain(bytes) => {
                    let wire = Wire::decode(&bytes)?;
                    let peer = self.channels[connection].peer.clone().ok_or_else(|| err("unpaired_device"))?;
                    let digest = Sha256::digest(&bytes).to_vec();
                    if self.seen.iter().any(|(p,r,d)| p == &peer && r == &wire.request_id && d != &digest) { return fail("request_content_conflict"); }
                    if self.seen.len() >= 2048 { self.seen.pop_front(); }
                    self.seen.push_back((peer.clone(), wire.request_id, digest));
                    self.receive(&peer, connection, wire.payload)?;
                }
            }
        }
        Ok(())
    }
    fn close(&mut self, connection: &str) {
        let peer = self.channels.remove(connection).and_then(|c| c.peer);
        self.emit(json!({"event":"socket_close","connection_id":connection}));
        if let Some(peer) = peer {
            self.peer_event(&peer, false);
            let ids: Vec<_> = self.sessions.iter().filter(|(_,s)| !s.phase.terminal() && s.other(&self.id) == peer).map(|(&id,_)| id).collect();
            for id in ids { let _ = self.with_session(id, |core,s| {
                if s.binding.source_device_id == core.id {
                    core.request_stop(s);
                    for c in s.chunks.values_mut() { if c.status == Ack::Received { c.status = Ack::Unknown; } }
                } else { core.pause_receiver(s)?; }
                s.phase = if s.has_unknown() { Phase::Unknown } else { Phase::Paused }; core.snapshot(s); Ok(())
            }); }
        }
    }
    fn add_session(&mut self, b: Binding, source: bool) -> Result<Uuid> {
        b.validate(now_ms())?;
        if self.sessions.len() >= 64 || (source && self.active_source.is_some()) || (!source && self.active_target.is_some()) { return fail("busy"); }
        let other = if source { &b.target_device_id } else { &b.source_device_id };
        self.journal.session(b.session_id, other, now_ms())?;
        let id = b.session_id; let s = Session::new(b);
        if source { self.active_source = Some(id); } else { self.active_target = Some(id); }
        self.snapshot(&s); self.sessions.insert(id,s); Ok(id)
    }
    fn request_stop(&mut self, s: &mut Session) {
        s.held = false;
        if s.stopped || s.stop_requested { return; }
        s.stop_requested = true; s.finalizing = Some(Instant::now());
        if !matches!(s.phase, Phase::Paused | Phase::Unknown | Phase::Cancelled) { s.phase = Phase::Finalizing; }
        self.emit(json!({"event":"stop_input","session_id":s.binding.session_id}));
        let _ = self.send(&s.other(&self.id), Payload::SessionState { session_id:s.binding.session_id, phase:s.phase });
        self.snapshot(s);
    }
    fn pause_receiver(&mut self, s: &mut Session) -> Result<()> {
        if !s.phase.terminal() { s.phase = Phase::Paused; }
        for (&n,c) in &mut s.chunks {
            if c.status == Ack::Received && s.inflight != Some((n,true)) {
                c.status = Ack::NotApplied; self.journal.record(s.binding.session_id,n,Ack::NotApplied)?;
                let _ = self.send(&s.binding.source_device_id, Payload::ChunkAck { session_id:s.binding.session_id,sequence:n,ack_status:Ack::NotApplied });
            }
        }
        if s.inflight.is_some_and(|(_,claimed)| !claimed) { s.inflight = None; }
        Ok(())
    }
    fn cancel(&mut self, s: &mut Session, notify: bool) -> Result<()> {
        if s.cancelled { return Ok(()); }
        s.cancelled = true; s.held = false; s.phase = Phase::Cancelled;
        if s.binding.source_device_id == self.id {
            if !s.stopped { s.stop_requested = true; s.finalizing = Some(Instant::now()); self.emit(json!({"event":"cancel_input","session_id":s.binding.session_id})); }
        } else { self.pause_receiver(s)?; }
        if notify { let _ = self.send(&s.other(&self.id),Payload::SessionCancel { session_id:s.binding.session_id }); }
        self.snapshot(s); Ok(())
    }
    fn freeze(&mut self, s: &mut Session, text: String, is_final: bool) -> Result<()> {
        validate_text(&text)?;
        if s.cancelled || s.binding.source_device_id != self.id || s.next_send > 4096
            || s.chunks.values().map(|c| c.text.len()).sum::<usize>() + text.len() > 256 * 1024 { return fail("session_text_limit"); }
        let seq = s.next_send; s.next_send += 1;
        let message = Payload::TextChunk { session_id:s.binding.session_id, sequence:seq, context_token:s.binding.context_token.clone(), text:text.clone(), is_final };
        let status = if self.send(&s.binding.target_device_id,message).is_ok() { Ack::Received } else { Ack::NotApplied };
        s.chunks.insert(seq,Chunk { text,status,is_final });
        if status == Ack::NotApplied { s.phase = Phase::Paused; self.request_stop(s); }
        self.snapshot(s); Ok(())
    }
    fn end_source(&mut self, s: &mut Session) -> Result<()> {
        if s.cancelled { s.phase = Phase::Cancelled; self.snapshot(s); return Ok(()); }
        s.last_sequence = Some(s.next_send - 1); s.phase = Phase::Committing;
        if self.send(&s.binding.target_device_id,Payload::SessionEnd { session_id:s.binding.session_id,last_sequence:s.next_send-1 }).is_err() { s.phase = Phase::Paused; }
        else if s.chunks.values().all(|c| c.status == Ack::Applied) { s.phase = Phase::Done; }
        self.snapshot(s); Ok(())
    }
    fn pump(&mut self, s: &mut Session) {
        if !s.can_inject() || s.inflight.is_some() { return; }
        if let Some(c) = s.chunks.get(&s.next_receive) {
            if c.status == Ack::Received {
                s.inflight = Some((s.next_receive,false));
                self.emit(json!({"event":"inject","session_id":s.binding.session_id,"sequence":s.next_receive,"text":c.text,"context_token":s.binding.context_token}));
            }
        }
    }
    fn finish_receiver(&mut self, s: &mut Session) {
        if !s.cancelled && s.last_sequence.is_some_and(|n| s.next_receive == n + 1) && !s.has_unknown() { s.phase = Phase::Done; }
    }
    fn injection_result(&mut self, s: &mut Session, seq: u64, requested: Ack) -> Result<()> {
        if s.binding.target_device_id != self.id || s.inflight.map(|(n,_)| n) != Some(seq) || requested == Ack::Received { return fail("invalid_injection_receipt"); }
        let status = if self.journal.record(s.binding.session_id,seq,requested).is_ok() { requested } else { Ack::Unknown };
        let c = s.chunks.get_mut(&seq).ok_or_else(|| err("unknown_chunk"))?; c.status = status;
        s.inflight = None;
        if status == Ack::Applied { s.next_receive += 1; }
        else if !s.cancelled { s.phase = if status == Ack::Unknown { Phase::Unknown } else { Phase::Paused }; }
        let _ = self.send(&s.binding.source_device_id,Payload::ChunkAck { session_id:s.binding.session_id,sequence:seq,ack_status:status });
        self.finish_receiver(s); self.snapshot(s); self.pump(s); Ok(())
    }
    fn receive(&mut self, peer: &str, connection: &str, payload: Payload) -> Result<()> {
        match payload {
            Payload::Hello { device_id,name } => {
                if device_id != peer || name.len() > 128 || name.chars().any(char::is_control) { return fail("invalid_peer_identity"); }
                self.channels.get_mut(connection).ok_or_else(|| err("target_offline"))?.name = name;
                self.peer_event(peer,true); return Ok(());
            }
            Payload::PairConfirm => {
                self.channels.get_mut(connection).ok_or_else(|| err("target_offline"))?.remote_confirmed = true;
                if !self.trust.contains_key(peer) { self.emit(json!({"event":"pair_requested","peer_id":peer,"code":self.channels[connection].code,"name":self.channels[connection].name})); }
                return self.maybe_pair(peer);
            }
            _ if !self.trust.contains_key(peer) => return fail("unpaired_device"),
            _ => {}
        }
        match payload {
            Payload::BindRequest { binding:b } => {
                if b.source_device_id != peer || b.target_device_id != self.id || b.controller_device_id != peer || !b.context_token.is_empty() { return fail("invalid_binding"); }
                if let Some(s) = self.sessions.get(&b.session_id) {
                    if s.binding.source_device_id != peer { return fail("session_conflict"); }
                    return Ok(());
                }
                let id = self.add_session(b,false)?;
                self.emit(json!({"event":"bind_target","session_id":id}));
            }
            Payload::SessionBound { binding:b } => {
                b.validate(now_ms())?;
                self.with_session(b.session_id, |core,s| {
                    if s.binding.source_device_id != core.id || s.binding.target_device_id != peer || b.source_device_id != core.id || b.target_device_id != peer
                        || b.controller_device_id != s.binding.controller_device_id || b.input_mode != s.binding.input_mode || !valid_context(&b.context_token) { return fail("invalid_binding"); }
                    if s.phase != Phase::Preparing || s.stop_requested { return Ok(()); }
                    s.binding = b; core.emit(json!({"event":"prepare_input","binding":s.binding})); core.snapshot(s); Ok(())
                })?;
            }
            Payload::SessionStart { binding:b } => {
                if !self.trust.get(peer).is_some_and(|p| p.allow_remote) {
                    self.send(peer,Payload::Error { session_id:Some(b.session_id),code:"remote_not_authorized".into() })?; return Ok(());
                }
                if b.source_device_id != self.id || b.target_device_id != peer || b.controller_device_id != peer || !valid_context(&b.context_token) { return fail("invalid_binding"); }
                if let Some(s) = self.sessions.get(&b.session_id) {
                    if s.binding.controller_device_id != peer || s.binding.context_token != b.context_token || s.binding.input_mode != b.input_mode { return fail("session_conflict"); }
                    let phase = s.phase; self.send(peer,Payload::SessionState { session_id:b.session_id,phase })?; return Ok(());
                }
                let id = match self.add_session(b,true) { Ok(id) => id, Err(_) => { self.send(peer,Payload::Error {session_id:None,code:"busy_or_expired_session".into()})?; return Ok(()); } };
                let b = self.sessions[&id].binding.clone(); self.emit(json!({"event":"prepare_input","binding":b}));
            }
            Payload::ChunkQuery { session_id,sequence } => {
                self.journal.authorize(session_id,peer,now_ms())?;
                let status = self.journal.query(session_id,sequence)?;
                self.send(peer,Payload::ChunkAck { session_id,sequence,ack_status:status })?;
            }
            Payload::Error { session_id,code } => {
                if code.len() > 64 || !code.bytes().all(|c| c.is_ascii_lowercase() || c == b'_') { return fail("invalid_error_code"); }
                self.emit(json!({"event":"error","session_id":session_id,"code":code}));
                if let Some(id) = session_id { let _ = self.with_session(id, |core,s| {
                    if s.other(&core.id) != peer { return fail("unauthorized_session"); }
                    if s.binding.source_device_id == core.id { core.request_stop(s); } else { core.pause_receiver(s)?; }
                    s.phase = Phase::Paused; s.held = false; core.snapshot(s); Ok(())
                }); }
            }
            other => {
                let id = match &other {
                    Payload::SessionReady {session_id} | Payload::SessionState {session_id,..} | Payload::SessionKeepalive {session_id}
                    | Payload::SessionStop {session_id} | Payload::SessionCancel {session_id} | Payload::TextChunk {session_id,..}
                    | Payload::ChunkAck {session_id,..} | Payload::SessionEnd {session_id,..} | Payload::SessionPause {session_id}
                    | Payload::SessionResume {session_id,..} => *session_id,
                    _ => return fail("invalid_message"),
                };
                self.journal.authorize(id,peer,now_ms())?;
                self.with_session(id, |core,s| {
                    if s.other(&core.id) != peer { return fail("unauthorized_session"); }
                    match other {
                        Payload::SessionReady {..} => {
                            if peer != s.binding.source_device_id { return fail("unauthorized_session"); }
                            if s.phase == Phase::Preparing { s.phase = Phase::Ready; } core.snapshot(s);
                        }
                        Payload::SessionState {phase,..} => {
                            if peer != s.binding.source_device_id { return fail("unauthorized_session"); }
                            if !matches!(s.phase,Phase::Paused|Phase::Unknown|Phase::Cancelled|Phase::Done) && !phase.terminal() { s.phase = phase; } core.snapshot(s);
                        }
                        Payload::SessionKeepalive {..} => {
                            if peer != s.binding.controller_device_id || s.binding.source_device_id != core.id || s.stop_requested || !matches!(s.phase,Phase::Preparing|Phase::Ready|Phase::Listening) { return Ok(()); }
                            s.lease = Instant::now();
                        }
                        Payload::SessionStop {..} => {
                            if peer != s.binding.controller_device_id || s.binding.source_device_id != core.id { return fail("unauthorized_session"); }
                            core.request_stop(s);
                        }
                        Payload::SessionCancel {..} => core.cancel(s,false)?,
                        Payload::TextChunk {sequence,context_token,text,is_final,..} => {
                            if peer != s.binding.source_device_id || sequence == 0 || sequence > 4096 { return fail("unauthorized_chunk"); }
                            validate_text(&text)?;
                            if let Some(status) = core.journal.register(id,sequence,&text)? {
                                if status != Ack::NotApplied || !s.retry_allowed.remove(&sequence) || context_token != s.binding.context_token {
                                    core.send(peer,Payload::ChunkAck {session_id:id,sequence,ack_status:status})?; return Ok(());
                                }
                                core.journal.record(id,sequence,Ack::Received)?;
                            }
                            let safe = context_token == s.binding.context_token && s.can_inject() && sequence >= s.next_receive
                                && sequence < s.next_receive + MAX_QUEUE as u64 && s.chunks.values().map(|c| c.text.len()).sum::<usize>() + text.len() <= 256*1024;
                            let status = if safe { Ack::Received } else { Ack::NotApplied };
                            if status == Ack::NotApplied { core.journal.record(id,sequence,status)?; }
                            if s.chunks.len() < 4096 { s.chunks.insert(sequence,Chunk { text,status,is_final }); }
                            core.send(peer,Payload::ChunkAck {session_id:id,sequence,ack_status:status})?;
                            core.snapshot(s); core.pump(s);
                        }
                        Payload::ChunkAck {sequence,ack_status,..} => {
                            if peer != s.binding.target_device_id { return fail("unauthorized_ack"); }
                            let c = s.chunks.get_mut(&sequence).ok_or_else(|| err("unknown_chunk"))?;
                            // Delayed transport ACKs must not downgrade confirmed or unknown outcomes.
                            if ack_status != Ack::Received || c.status == Ack::Received { if c.status != Ack::Applied { c.status = ack_status; } }
                            if !s.cancelled {
                                if c.status == Ack::Unknown { s.phase = Phase::Unknown; core.request_stop(s); }
                                else if c.status == Ack::NotApplied { s.phase = Phase::Paused; core.request_stop(s); }
                                else if s.stopped && s.last_sequence.is_some() && s.chunks.values().all(|c| c.status == Ack::Applied) { s.phase = Phase::Done; }
                            }
                            core.snapshot(s);
                        }
                        Payload::SessionEnd {last_sequence,..} => {
                            if peer != s.binding.source_device_id || last_sequence > 4096 || s.chunks.keys().any(|n| *n > last_sequence) { return fail("invalid_session_end"); }
                            s.last_sequence = Some(last_sequence); core.finish_receiver(s); core.snapshot(s);
                        }
                        Payload::SessionPause {..} => {
                            s.phase = Phase::Paused; if s.binding.source_device_id == core.id { core.request_stop(s); } else { core.pause_receiver(s)?; } core.snapshot(s);
                        }
                        Payload::SessionResume {context_token,target_app,..} => {
                            if peer != s.binding.target_device_id || !valid_context(&context_token) || s.cancelled || s.has_unknown() { return fail("unsafe_resume"); }
                            s.binding.context_token = context_token; s.binding.target_app = target_app; s.phase = Phase::Committing;
                            let pending: Vec<_> = s.chunks.iter().filter(|(_,c)| c.status == Ack::NotApplied).map(|(&n,c)| (n,c.text.clone(),c.is_final)).collect();
                            for (sequence,text,is_final) in pending {
                                core.send(peer,Payload::TextChunk {session_id:id,sequence,text,is_final,context_token:s.binding.context_token.clone()})?;
                                s.chunks.get_mut(&sequence).ok_or_else(|| err("unknown_chunk"))?.status = Ack::Received;
                            }
                            if let Some(last_sequence) = s.last_sequence { core.send(peer,Payload::SessionEnd {session_id:id,last_sequence})?; }
                            core.snapshot(s);
                        }
                        _ => return fail("invalid_message"),
                    }
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
    pub fn command(&mut self, v: Value) -> Result<Value> {
        if self.faulted { return fail("core_restart_required"); }
        let op = string(&v,"op")?;
        match op.as_str() {
            "open" => {
                let connection = string(&v,"connection_id")?;
                if self.channels.len() >= 8 || self.channels.contains_key(&connection) { return fail("connection_limit"); }
                let expected = v["expected_peer"].as_str().map(str::to_owned);
                if expected.as_ref().is_some_and(|s| !valid_id(s)) { return fail("invalid_peer_identity"); }
                let (c,events) = Channel::new(&self.private,v["initiator"].as_bool().unwrap_or(false),expected)?;
                self.channels.insert(connection.clone(),c); self.channel_events(&connection,events)?;
            }
            "bytes" => {
                let connection = string(&v,"connection_id")?;
                let data = B64.decode(string(&v,"data")?).map_err(|_| err("invalid_frame"))?;
                let result = self.channels.get_mut(&connection).ok_or_else(|| err("target_offline"))?.receive(&data)
                    .and_then(|events| self.channel_events(&connection,events));
                if let Err(error) = result { self.close(&connection); return Err(error); }
            }
            "closed" => self.close(&string(&v,"connection_id")?),
            "pair" => {
                let peer = string(&v,"peer_id")?; let connection = self.connection(&peer)?;
                self.channels.get_mut(&connection).ok_or_else(|| err("target_offline"))?.local_confirmed = true;
                self.send_on(&connection,Payload::PairConfirm)?; self.maybe_pair(&peer)?;
            }
            "revoke" | "remote_permission" => {
                let peer = string(&v,"peer_id")?;
                if op == "revoke" { self.trust.remove(&peer); }
                else { self.trust.get_mut(&peer).ok_or_else(|| err("unpaired_device"))?.allow_remote = v["allowed"].as_bool().unwrap_or(false); }
                self.save_trust();
                if op == "revoke" || !v["allowed"].as_bool().unwrap_or(false) {
                    if let Some(id) = self.active_source { let _ = self.with_session(id, |core,s| { if s.binding.controller_device_id == peer || (op == "revoke" && s.other(&core.id) == peer) { core.cancel(s,true)?; } Ok(()) }); }
                }
                if op == "revoke" { if let Ok(connection) = self.connection(&peer) { self.close(&connection); } }
                self.peer_event(&peer,self.connection(&peer).is_ok());
            }
            "begin" => {
                let peer = string(&v,"peer_id")?;
                if !self.trust.contains_key(&peer) { return fail("unpaired_device"); } self.connection(&peer)?;
                let mode: Mode = serde_json::from_value(v["mode"].clone()).map_err(|_| err("invalid_input_mode"))?;
                let remote = v["remote"].as_bool().unwrap_or(false); let id = Uuid::new_v4();
                let b = Binding {session_id:id,source_device_id:if remote {peer.clone()} else {self.id.clone()},target_device_id:if remote {self.id.clone()} else {peer.clone()},controller_device_id:self.id.clone(),input_mode:mode,context_token:if remote {string(&v,"context_token")?} else {String::new()},target_app:v["target_app"].as_str().unwrap_or("").into(),created_ms:now_ms()};
                if remote && !valid_context(&b.context_token) { return fail("invalid_context"); }
                self.add_session(b.clone(),!remote)?;
                self.send(&peer,if remote {Payload::SessionStart {binding:b}} else {Payload::BindRequest {binding:b}})?;
                return Ok(json!({"session_id":id}));
            }
            "tick" => self.tick()?,
            "forget_recovery" => {
                let id = sid(&v)?;
                if self.active_source == Some(id) || self.active_target == Some(id) { return fail("session_still_active"); }
                self.sessions.remove(&id); self.emit(json!({"event":"recovery_cleared","session_id":id}));
            }
            _ => {
                let id = sid(&v)?;
                return self.with_session(id,|core,s| {
                    let source = s.binding.source_device_id == core.id;
                    match op.as_str() {
                        "bound" => {
                            if source || s.phase != Phase::Preparing { return fail("invalid_state"); }
                            let token = string(&v,"context_token")?; if !valid_context(&token) { return fail("invalid_context"); }
                            s.binding.context_token = token; s.binding.target_app = string(&v,"target_app")?;
                            core.send(&s.binding.source_device_id,Payload::SessionBound {binding:s.binding.clone()})?; core.snapshot(s);
                        }
                        "ready" | "listening" => {
                            if !source || s.stop_requested || s.cancelled { return fail("source_not_ready"); }
                            if op == "ready" && s.phase == Phase::Preparing {
                                s.phase = Phase::Ready; core.send(&s.binding.target_device_id,Payload::SessionReady {session_id:id})?;
                            } else if op == "listening" && s.phase == Phase::Ready {
                                s.phase = Phase::Listening; core.send(&s.binding.target_device_id,Payload::SessionState {session_id:id,phase:s.phase})?;
                            } else { return fail("invalid_state"); } core.snapshot(s);
                        }
                        "draft" => {
                            if !source || s.cancelled || s.frozen || s.phase.terminal() { return fail("stale_input_callback"); }
                            let text = string(&v,"text")?; if text.len() > MAX_TEXT { return fail("draft_limit"); } s.draft = text; core.snapshot(s);
                        }
                        "apple_result" => {
                            if !source || s.binding.input_mode != Mode::AppleLocal || !s.phase.accepts_text() || s.cancelled || s.stopped { return fail("stale_input_callback"); }
                            let ready = s.stable.observe(number(&v,"start")? as i64,number(&v,"end")? as i64,number(&v,"finalized_until")? as i64,string(&v,"text")?)?;
                            s.draft = s.stable.draft(); for text in ready { core.freeze(s,text,false)?; } core.snapshot(s);
                        }
                        "source_stopped" => {
                            if !source { return fail("invalid_role"); }
                            let verified = v["verified"].as_bool().unwrap_or(false); s.stopped = verified; s.finalizing = None;
                            if !verified { s.phase = Phase::StopFailed; }
                            else if s.cancelled { s.phase = Phase::Cancelled; }
                            else if matches!(s.phase,Phase::Paused|Phase::Unknown) { }
                            else if s.binding.input_mode == Mode::DoubaoIme || !s.draft.is_empty() { s.phase = Phase::AwaitingConfirmation; }
                            else { core.end_source(s)?; }
                            let _ = core.send(&s.other(&core.id),Payload::SessionState {session_id:id,phase:s.phase}); core.snapshot(s);
                        }
                        "source_failed" => {
                            if source { core.request_stop(s); } else { core.pause_receiver(s)?; }
                            s.phase = Phase::Paused; s.held = false; core.emit(json!({"event":"error","session_id":id,"code":string(&v,"code")?}));
                            let _ = core.send(&s.other(&core.id),Payload::SessionPause {session_id:id}); core.snapshot(s);
                        }
                        "confirm_stopped" => {
                            if !source { return fail("invalid_role"); } s.stopped = true; s.finalizing = None;
                            s.phase = if s.cancelled {Phase::Cancelled} else {Phase::AwaitingConfirmation}; core.snapshot(s);
                        }
                        "confirm" => {
                            if !source || s.cancelled || s.frozen || !s.stopped || s.has_unknown() || !matches!(s.phase,Phase::AwaitingConfirmation|Phase::Paused) { return fail("unsafe_confirmation"); }
                            let text = string(&v,"text")?; if !text.is_empty() { validate_text(&text)?; }
                            s.frozen = true; s.phase = Phase::Committing; s.draft.clear();
                            if !text.is_empty() { core.freeze(s,text,true)?; }
                            if s.phase != Phase::Paused { core.end_source(s)?; }
                        }
                        "stop" => {
                            s.held = false;
                            if source { core.request_stop(s); }
                            else { core.send(&s.binding.source_device_id,Payload::SessionStop {session_id:id})?; if !s.phase.terminal() {s.phase=Phase::Finalizing;} core.snapshot(s); }
                        }
                        "cancel" => core.cancel(s,true)?,
                        "focus_invalid" => {
                            if source { return fail("invalid_role"); }
                            core.pause_receiver(s)?; core.send(&s.binding.source_device_id,Payload::SessionPause {session_id:id})?; core.snapshot(s);
                        }
                        "claim_injection" => {
                            let seq = number(&v,"sequence")?;
                            if source || !s.can_inject() || s.inflight != Some((seq,false)) { return Ok(json!({"allowed":false})); }
                            s.inflight = Some((seq,true)); return Ok(json!({"allowed":true}));
                        }
                        "injection_result" => {
                            let status: Ack = serde_json::from_value(v["status"].clone()).map_err(|_| err("invalid_receipt"))?;
                            core.injection_result(s,number(&v,"sequence")?,status)?;
                        }
                        "resume" => {
                            if source || s.cancelled || s.has_unknown() || s.inflight.is_some() { return fail("unsafe_resume"); }
                            let token = string(&v,"context_token")?; if !valid_context(&token) || token == s.binding.context_token { return fail("invalid_context"); }
                            s.binding.context_token = token.clone(); s.binding.target_app = string(&v,"target_app")?;
                            s.retry_allowed = s.chunks.iter().filter(|(_,c)| c.status == Ack::NotApplied).map(|(&n,_)| n).collect();
                            s.phase = Phase::Committing;
                            core.send(&s.binding.source_device_id,Payload::SessionResume {session_id:id,context_token:token,target_app:s.binding.target_app.clone()})?; core.snapshot(s);
                        }
                        "resolve_unknown" => {
                            if source || s.inflight.is_some() { return fail("resolve_on_target"); }
                            let seq = number(&v,"sequence")?; let c = s.chunks.get_mut(&seq).ok_or_else(|| err("unknown_chunk"))?;
                            if c.status != Ack::Unknown { return fail("not_unknown"); }
                            let status = if v["applied"].as_bool().unwrap_or(false) {Ack::Applied} else {Ack::NotApplied};
                            core.journal.record(id,seq,status)?; c.status=status;
                            while s.chunks.get(&s.next_receive).is_some_and(|c| c.status==Ack::Applied) {s.next_receive+=1;}
                            if !s.cancelled {s.phase=Phase::Paused;}
                            core.send(&s.binding.source_device_id,Payload::ChunkAck {session_id:id,sequence:seq,ack_status:status})?; core.snapshot(s);
                        }
                        "query" => {
                            if !source { return fail("invalid_role"); }
                            for (&sequence,c) in &s.chunks { if c.status != Ack::Applied {core.send(&s.binding.target_device_id,Payload::ChunkQuery {session_id:id,sequence})?;} }
                        }
                        _ => return fail("unknown_command"),
                    }
                    Ok(json!({"ok":true}))
                });
            }
        }
        Ok(json!({"ok":true}))
    }
    fn tick(&mut self) -> Result<()> {
        let close: Vec<String> = self.channels.iter().filter(|(_,c)| (c.peer.is_none() && c.created.elapsed()>Duration::from_secs(10))
            || (c.peer.as_ref().is_some_and(|p| !self.trust.contains_key(p)) && c.created.elapsed()>Duration::from_secs(60))
            || c.last_rx.elapsed()>Duration::from_secs(45)).map(|(id,_)| id.clone()).collect();
        for id in close { self.close(&id); }
        if self.heartbeat.elapsed()>Duration::from_secs(10) {
            self.heartbeat=Instant::now(); let peers:Vec<String>=self.trust.keys().cloned().collect();
            for p in peers {let _=self.send(&p,Payload::Hello {device_id:self.id.clone(),name:self.name.clone()});}
        }
        let ids:Vec<_>=self.sessions.keys().copied().collect();
        for id in ids { self.with_session(id,|core,s| {
            if s.binding.source_device_id==core.id {
                if !s.stopped && !s.stop_requested && (s.started.elapsed()>core.max_session || (s.binding.controller_device_id!=core.id && s.lease.elapsed()>core.lease)) {core.request_stop(s);}
                if s.finalizing.is_some_and(|t| t.elapsed()>core.finalizing) {
                    s.finalizing=None;
                    s.phase=if s.binding.input_mode==Mode::DoubaoIme {Phase::StopFailed} else if s.cancelled {Phase::Cancelled} else {Phase::AwaitingConfirmation};
                    core.emit(json!({"event":"abort_input","session_id":id})); core.snapshot(s);
                }
            } else if s.held && s.binding.controller_device_id==core.id && matches!(s.phase,Phase::Preparing|Phase::Ready|Phase::Listening) && s.keepalive_sent.elapsed()>Duration::from_millis(750) {
                s.keepalive_sent=Instant::now(); let _=core.send(&s.binding.source_device_id,Payload::SessionKeepalive {session_id:id});
            }
            Ok(())
        })?; }
        Ok(())
    }
}
