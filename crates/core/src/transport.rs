use std::time::{Duration, Instant};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{err, fail, Result, protocol::MAX_FRAME};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"VoiceKeyboard/LAN/text-only/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity { pub private_key: String, pub public_key: String }
impl Identity {
    pub fn generate() -> Result<Self> {
        let pair = snow::Builder::new(PATTERN.parse().map_err(|_| err("crypto_error"))?).generate_keypair().map_err(|_| err("crypto_error"))?;
        Ok(Self { private_key: B64.encode(pair.private), public_key: B64.encode(pair.public) })
    }
    pub fn private_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let bytes = B64.decode(&self.private_key).map_err(|_| err("invalid_identity"))?;
        let key: [u8;32] = bytes.as_slice().try_into().map_err(|_| err("invalid_identity"))?;
        let public = x25519_dalek::x25519(key, x25519_dalek::X25519_BASEPOINT_BYTES);
        if B64.encode(public) != self.public_key { return fail("identity_key_mismatch"); }
        Ok(zeroize::Zeroizing::new(bytes))
    }
    pub fn id(&self) -> Result<String> { Ok(hex(&Sha256::digest(B64.decode(&self.public_key).map_err(|_| err("invalid_identity"))?))) }
}
pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

pub enum ChannelEvent { Write(Vec<u8>), Authenticated { peer: String, code: String }, Plain(Vec<u8>) }
enum Cipher { Handshake(Box<snow::HandshakeState>), Transport(Box<snow::TransportState>) }
pub struct Channel {
    cipher: Option<Cipher>, buffer: Vec<u8>, pub peer: Option<String>, pub code: String,
    pub name: String, pub local_confirmed: bool, pub remote_confirmed: bool,
    pub created: Instant, pub last_rx: Instant, window: Instant, messages: usize, expected: Option<String>,
}
impl Channel {
    pub fn new(private: &[u8], initiator: bool, expected: Option<String>) -> Result<(Self, Vec<ChannelEvent>)> {
        let builder = snow::Builder::new(PATTERN.parse().map_err(|_| err("crypto_error"))?).local_private_key(private).prologue(PROLOGUE);
        let handshake = if initiator { builder.build_initiator() } else { builder.build_responder() }.map_err(|_| err("crypto_error"))?;
        let now = Instant::now();
        let mut c = Self { cipher: Some(Cipher::Handshake(Box::new(handshake))), buffer: Vec::new(), peer: None, code: String::new(), name: String::new(), local_confirmed: false, remote_confirmed: false, created: now, last_rx: now, window: now, messages: 0, expected };
        let mut events = Vec::new();
        if initiator { c.handshake_write(&mut events)?; }
        Ok((c, events))
    }
    fn frame(bytes: &[u8]) -> Vec<u8> { let mut f = (bytes.len() as u32).to_be_bytes().to_vec(); f.extend(bytes); f }
    fn handshake_write(&mut self, events: &mut Vec<ChannelEvent>) -> Result<()> {
        let mut out = vec![0; MAX_FRAME];
        if let Some(Cipher::Handshake(h)) = self.cipher.as_mut() {
            let n = h.write_message(&[], &mut out).map_err(|_| err("handshake_failed"))?;
            events.push(ChannelEvent::Write(Self::frame(&out[..n])));
        }
        Ok(())
    }
    fn finish_handshake(&mut self, events: &mut Vec<ChannelEvent>) -> Result<()> {
        let finished = matches!(&self.cipher, Some(Cipher::Handshake(h)) if h.is_handshake_finished());
        if !finished { return Ok(()); }
        let Some(Cipher::Handshake(h)) = self.cipher.take() else { return fail("crypto_state"); };
        let remote = h.get_remote_static().ok_or_else(|| err("missing_identity"))?;
        let peer = hex(&Sha256::digest(remote));
        if self.expected.as_ref().is_some_and(|id| id != &peer) { return fail("peer_identity_changed"); }
        let digest = Sha256::digest(h.get_handshake_hash());
        let code = format!("{:06}", u32::from_be_bytes(digest[..4].try_into().map_err(|_| err("crypto_error"))?) % 1_000_000);
        self.peer = Some(peer.clone()); self.code = code.clone();
        self.cipher = Some(Cipher::Transport(Box::new(h.into_transport_mode().map_err(|_| err("crypto_error"))?)));
        events.push(ChannelEvent::Authenticated { peer, code });
        Ok(())
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<ChannelEvent>> {
        if bytes.len() > MAX_FRAME + 4 || self.buffer.len() + bytes.len() > 2 * (MAX_FRAME + 4) { return fail("buffer_limit"); }
        self.buffer.extend(bytes); self.last_rx = Instant::now();
        let mut events = Vec::new();
        loop {
            if self.buffer.len() < 4 { break; }
            let size = u32::from_be_bytes(self.buffer[..4].try_into().map_err(|_| err("invalid_frame"))?) as usize;
            if size == 0 || size > MAX_FRAME { return fail("frame_limit"); }
            if self.buffer.len() < size + 4 { break; }
            if self.window.elapsed() >= Duration::from_secs(1) { self.window = Instant::now(); self.messages = 0; }
            self.messages += 1;
            if self.messages > 100 { return fail("rate_limit"); }
            let frame = self.buffer[4..4 + size].to_vec(); self.buffer.drain(..4 + size);
            let mut plain = vec![0; MAX_FRAME];
            match self.cipher.as_mut().ok_or_else(|| err("crypto_state"))? {
                Cipher::Handshake(h) => {
                    let n = h.read_message(&frame, &mut plain).map_err(|_| err("handshake_failed"))?;
                    if n != 0 { return fail("handshake_payload_forbidden"); }
                    if !h.is_handshake_finished() && h.is_my_turn() { self.handshake_write(&mut events)?; }
                    self.finish_handshake(&mut events)?;
                }
                Cipher::Transport(t) => {
                    let n = t.read_message(&frame, &mut plain).map_err(|_| err("authentication_failed"))?;
                    plain.truncate(n); events.push(ChannelEvent::Plain(plain));
                }
            }
        }
        Ok(events)
    }
    pub fn encrypt(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.len() > MAX_FRAME - 32 { return fail("message_too_large"); }
        let Some(Cipher::Transport(t)) = self.cipher.as_mut() else { return fail("peer_not_ready"); };
        let mut out = vec![0; MAX_FRAME];
        let n = t.write_message(bytes, &mut out).map_err(|_| err("encryption_failed"))?;
        Ok(Self::frame(&out[..n]))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    fn pair() -> (Channel, Channel) {
        let a = Identity::generate().unwrap(); let b = Identity::generate().unwrap();
        let (mut a, first) = Channel::new(&a.private_bytes().unwrap(), true, Some(b.id().unwrap())).unwrap();
        let (mut b, _) = Channel::new(&b.private_bytes().unwrap(), false, None).unwrap();
        let ChannelEvent::Write(first) = &first[0] else { panic!() };
        let second = b.receive(first).unwrap(); let ChannelEvent::Write(second) = &second[0] else { panic!() };
        let third = a.receive(second).unwrap(); let ChannelEvent::Write(third) = &third[0] else { panic!() };
        b.receive(third).unwrap(); assert_eq!(a.code, b.code); (a,b)
    }
    #[test] fn authenticated_encryption_and_fragmented_frames() {
        let (mut a, mut b) = pair(); let encrypted = a.encrypt(b"private dictation").unwrap();
        assert!(!encrypted.windows(9).any(|w| w == b"dictation"));
        assert!(b.receive(&encrypted[..3]).unwrap().is_empty());
        let ev = b.receive(&encrypted[3..]).unwrap();
        assert!(matches!(&ev[0], ChannelEvent::Plain(p) if p == b"private dictation"));
        assert!(b.receive(&encrypted).is_err());
    }
    #[test] fn tampering_and_oversize_are_rejected() {
        let (mut a, mut b) = pair(); let mut encrypted = a.encrypt(b"text").unwrap();
        *encrypted.last_mut().unwrap() ^= 1; assert!(b.receive(&encrypted).is_err());
        assert!(a.receive(&u32::MAX.to_be_bytes()).is_err());
    }
    #[test] fn altered_identity_cannot_load() {
        let mut i = Identity::generate().unwrap(); i.public_key = B64.encode([0;32]); assert!(i.private_bytes().is_err());
    }
}
