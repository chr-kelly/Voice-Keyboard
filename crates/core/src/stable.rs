use std::collections::BTreeMap;
use crate::{fail, Result};

#[derive(Default)]
pub struct StableText {
    segments: BTreeMap<i64, (i64, String)>,
    committed_end: i64,
    finalized_until: i64,
}
impl StableText {
    // Audio positions are integer microseconds. Only provider finality freezes text.
    // An unchanged prefix, punctuation, and silence are deliberately not finality evidence.
    pub fn observe(&mut self, start: i64, end: i64, finalized_until: i64, text: String) -> Result<Vec<String>> {
        if start < 0 || end < start || finalized_until < 0 || text.len() > crate::protocol::MAX_TEXT { return fail("invalid_audio_range"); }
        if end <= self.committed_end { return Ok(Vec::new()); }
        if start < self.committed_end { return fail("finalized_revision"); }
        self.segments.retain(|&s, (e, _)| *e <= start || s >= end);
        self.segments.insert(start, (end, text));
        self.finalized_until = self.finalized_until.max(finalized_until);
        let ready: Vec<i64> = self.segments.iter().take_while(|(_, (e, _))| *e <= self.finalized_until).map(|(&s, _)| s).collect();
        let mut output = Vec::new();
        for start in ready {
            if let Some((end, text)) = self.segments.remove(&start) {
                self.committed_end = self.committed_end.max(end);
                if !text.is_empty() { output.push(text); }
            }
        }
        Ok(output)
    }
    pub fn draft(&self) -> String { self.segments.values().map(|(_, t)| t.as_str()).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn draft_can_be_revised() {
        let mut s = StableText::default();
        assert!(s.observe(0, 10, 0, "登陆".into()).unwrap().is_empty());
        assert!(s.observe(0, 10, 0, "登录".into()).unwrap().is_empty());
        assert_eq!(s.draft(), "登录");
        assert_eq!(s.observe(0, 10, 10, "登录".into()).unwrap(), vec!["登录"]);
        assert!(s.draft().is_empty());
    }
    #[test] fn finality_flushes_prior_volatile_ranges() {
        let mut s = StableText::default();
        s.observe(0, 10, 0, "中文".into()).unwrap();
        assert_eq!(s.observe(10, 20, 20, " English 👩🏽‍💻".into()).unwrap(), vec!["中文", " English 👩🏽‍💻"]);
    }
    #[test] fn committed_text_is_never_retracted() {
        let mut s = StableText::default();
        s.observe(0, 10, 10, "登陆".into()).unwrap();
        assert!(s.observe(0, 10, 10, "登录".into()).unwrap().is_empty());
        assert!(s.observe(5, 20, 20, "replacement".into()).is_err());
    }
    #[test] fn silence_is_not_finality() {
        let mut s = StableText::default();
        for _ in 0..100 { assert!(s.observe(0, 10, 0, "一句话。".into()).unwrap().is_empty()); }
    }
    #[test] fn empty_final_result_advances_range_without_chunk() {
        let mut s = StableText::default();
        s.observe(0, 10, 0, "撤回".into()).unwrap();
        assert!(s.observe(0, 10, 10, String::new()).unwrap().is_empty());
        assert_eq!(s.observe(10, 20, 20, "保留".into()).unwrap(), vec!["保留"]);
    }
}
