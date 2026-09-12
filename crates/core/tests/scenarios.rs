use std::{sync::Arc, time::Duration};
use serde_json::{json, Value};
use voice_keyboard_core::{Core, generate_identity};
use uuid::Uuid;

struct Lab {
    a: Arc<Core>, b: Arc<Core>, a_events: Vec<Value>, b_events: Vec<Value>, _dir: tempfile::TempDir,
}
impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let make = |name: &str| Core::new(json!({"identity":serde_json::from_str::<Value>(&generate_identity().unwrap()).unwrap(),"name":name,"journal_path":dir.path().join(format!("{name}.db")).to_str().unwrap(),"lease_ms":1500,"finalizing_ms":1000}).to_string()).unwrap();
        let a=make("A"); let b=make("B");
        let mut lab=Self {a,b,a_events:vec![],b_events:vec![],_dir:dir};
        Self::call(&lab.b,json!({"op":"open","connection_id":"b","initiator":false}));
        Self::call(&lab.a,json!({"op":"open","connection_id":"a","initiator":true,"expected_peer":lab.b.device_id().unwrap()}));
        lab.pump(); lab
    }
    fn call(core:&Core, command:Value)->Value { serde_json::from_str(&core.dispatch(command.to_string()).unwrap()).unwrap() }
    fn pump(&mut self) {
        for _ in 0..100 {
            let mut moved=false;
            for (from,to,connection,events) in [(&self.a,&self.b,"b",&mut self.a_events),(&self.b,&self.a,"a",&mut self.b_events)] {
                for event in from.poll_events().unwrap() {
                    moved=true; let e:Value=serde_json::from_str(&event).unwrap();
                    if e["event"]=="socket_send" {Self::call(to,json!({"op":"bytes","connection_id":connection,"data":e["data"]}));}
                    else {events.push(e);}
                }
            }
            if !moved {return;}
        }
        panic!("non-quiescent core");
    }
    fn pair(&mut self) {
        let a_code=self.a_events.iter().find(|e|e["event"]=="secure_channel").unwrap()["code"].clone();
        let b_code=self.b_events.iter().find(|e|e["event"]=="secure_channel").unwrap()["code"].clone(); assert_eq!(a_code,b_code);
        Self::call(&self.a,json!({"op":"pair","peer_id":self.b.device_id().unwrap()})); self.pump();
        assert!(!self.a_events.iter().any(|e|e["event"]=="trust_changed"));
        Self::call(&self.b,json!({"op":"pair","peer_id":self.a.device_id().unwrap()})); self.pump();
        assert!(self.a_events.iter().any(|e|e["event"]=="trust_changed"));
        assert!(self.b_events.iter().any(|e|e["event"]=="trust_changed"));
    }
    fn local(&mut self, mode:&str)->Value {
        let id=Self::call(&self.a,json!({"op":"begin","peer_id":self.b.device_id().unwrap(),"mode":mode,"remote":false}))["session_id"].clone(); self.pump();
        Self::call(&self.b,json!({"op":"bound","session_id":id,"context_token":Uuid::new_v4(),"target_app":"TextEdit"})); self.pump();
        Self::call(&self.a,json!({"op":"ready","session_id":id}));
        Self::call(&self.a,json!({"op":"listening","session_id":id})); self.pump(); id
    }
    fn apple(&mut self,id:&Value,start:u64,end:u64,text:&str) {
        Self::call(&self.a,json!({"op":"apple_result","session_id":id,"start":start,"end":end,"finalized_until":end,"text":text})); self.pump();
    }
    fn apply(&mut self,id:&Value,sequence:u64,status:&str) {
        assert_eq!(Self::call(&self.b,json!({"op":"claim_injection","session_id":id,"sequence":sequence}))["allowed"],true);
        Self::call(&self.b,json!({"op":"injection_result","session_id":id,"sequence":sequence,"status":status})); self.pump();
    }
    fn last<'a>(events:&'a [Value],id:&Value)->&'a Value { events.iter().rev().find(|e|e["event"]=="session" && &e["binding"]["session_id"]==id).unwrap() }
    fn injections(&self)->usize {self.b_events.iter().filter(|e|e["event"]=="inject").count()}
}

#[test] fn unpaired_device_cannot_begin_and_pairing_needs_both_parties() {
    let mut l=Lab::new();
    assert!(l.a.dispatch(json!({"op":"begin","peer_id":l.b.device_id().unwrap(),"mode":"apple_local","remote":false}).to_string()).is_err()); l.pair();
}
#[test] fn apple_streams_ordered_chunks_and_only_applied_means_done() {
    let mut l=Lab::new(); l.pair(); let id=l.local("apple_local");
    l.apple(&id,0,10,"帮我修改"); l.apple(&id,10,20," login button。");
    assert_eq!(l.injections(),1); // one platform side effect in flight
    l.apply(&id,1,"applied"); assert_eq!(l.injections(),2);
    Lab::call(&l.a,json!({"op":"stop","session_id":id}));
    Lab::call(&l.a,json!({"op":"source_stopped","session_id":id,"verified":true})); l.pump();
    assert_ne!(Lab::last(&l.a_events,&id)["phase"],"done");
    l.apply(&id,2,"applied");
    assert_eq!(Lab::last(&l.a_events,&id)["phase"],"done"); assert_eq!(Lab::last(&l.b_events,&id)["phase"],"done");
}
#[test] fn partial_revisions_never_reach_receiver() {
    let mut l=Lab::new();l.pair();let id=l.local("apple_local");
    for text in ["登陆","登录"] {Lab::call(&l.a,json!({"op":"apple_result","session_id":id,"start":0,"end":10,"finalized_until":0,"text":text}));l.pump();}
    assert_eq!(l.injections(),0); l.apple(&id,0,10,"登录");assert_eq!(l.injections(),1);
    assert_eq!(Lab::last(&l.b_events,&id)["chunks"][0]["text"],"登录");
}
#[test] fn unknown_blocks_next_chunk_and_query_does_not_reinject() {
    let mut l=Lab::new();l.pair();let id=l.local("apple_local"); l.apple(&id,0,10,"first");l.apple(&id,10,20,"second");
    l.apply(&id,1,"unknown");assert_eq!(l.injections(),1);
    Lab::call(&l.a,json!({"op":"query","session_id":id}));l.pump();assert_eq!(l.injections(),1);
    assert_eq!(Lab::last(&l.a_events,&id)["phase"],"unknown");
    assert!(l.b.dispatch(json!({"op":"resume","session_id":id,"context_token":Uuid::new_v4(),"target_app":"TextEdit"}).to_string()).is_err());
}
#[test] fn escape_prevents_unclaimed_actions_and_late_callbacks() {
    let mut l=Lab::new();l.pair();let id=l.local("apple_local"); l.apple(&id,0,10,"keep in recovery");
    Lab::call(&l.b,json!({"op":"cancel","session_id":id}));l.pump();
    assert_eq!(Lab::call(&l.b,json!({"op":"claim_injection","session_id":id,"sequence":1}))["allowed"],false);
    assert!(l.a.dispatch(json!({"op":"apple_result","session_id":id,"start":10,"end":20,"finalized_until":20,"text":"late"}).to_string()).is_err());
    assert_eq!(Lab::last(&l.b_events,&id)["chunks"][0]["status"],"not_applied");
}
#[test] fn cancellation_preserves_actual_inflight_result() {
    let mut l=Lab::new();l.pair();let id=l.local("apple_local");l.apple(&id,0,10,"already attempted");
    Lab::call(&l.b,json!({"op":"claim_injection","session_id":id,"sequence":1}));
    Lab::call(&l.b,json!({"op":"cancel","session_id":id}));l.pump();
    Lab::call(&l.b,json!({"op":"injection_result","session_id":id,"sequence":1,"status":"applied"}));l.pump();
    assert_eq!(Lab::last(&l.b_events,&id)["phase"],"cancelled"); assert_eq!(Lab::last(&l.b_events,&id)["chunks"][0]["status"],"applied");
}
#[test] fn doubao_waits_for_verified_stop_and_explicit_confirmation_once() {
    let mut l=Lab::new();l.pair();let id=l.local("doubao_ime");
    Lab::call(&l.a,json!({"op":"draft","session_id":id,"text":"完整段落"}));
    Lab::call(&l.a,json!({"op":"stop","session_id":id}));
    Lab::call(&l.a,json!({"op":"source_stopped","session_id":id,"verified":false}));l.pump();assert_eq!(l.injections(),0);
    assert!(l.a.dispatch(json!({"op":"confirm","session_id":id,"text":"完整段落"}).to_string()).is_err());
    Lab::call(&l.a,json!({"op":"confirm_stopped","session_id":id}));
    Lab::call(&l.a,json!({"op":"confirm","session_id":id,"text":"完整段落"}));l.pump();assert_eq!(l.injections(),1);
    assert!(l.a.dispatch(json!({"op":"confirm","session_id":id,"text":"完整段落"}).to_string()).is_err());
}
#[test] fn pairing_does_not_grant_remote_microphone_permission() {
    let mut l=Lab::new();l.pair();
    let id=Lab::call(&l.b,json!({"op":"begin","peer_id":l.a.device_id().unwrap(),"mode":"apple_local","remote":true,"context_token":Uuid::new_v4(),"target_app":"TextEdit"}))["session_id"].clone();l.pump();
    assert!(!l.a_events.iter().any(|e|e["event"]=="prepare_input"));
    assert_eq!(Lab::last(&l.b_events,&id)["phase"],"paused");
}
#[test] fn remote_lease_loss_stops_source_and_stop_is_idempotent() {
    let mut l=Lab::new();l.pair();Lab::call(&l.a,json!({"op":"remote_permission","peer_id":l.b.device_id().unwrap(),"allowed":true}));l.pump();
    let id=Lab::call(&l.b,json!({"op":"begin","peer_id":l.a.device_id().unwrap(),"mode":"apple_local","remote":true,"context_token":Uuid::new_v4(),"target_app":"TextEdit"}))["session_id"].clone();l.pump();
    Lab::call(&l.a,json!({"op":"ready","session_id":id}));Lab::call(&l.a,json!({"op":"listening","session_id":id}));l.pump();
    std::thread::sleep(Duration::from_millis(1600));Lab::call(&l.a,json!({"op":"tick"}));l.pump();
    assert_eq!(l.a_events.iter().filter(|e|e["event"]=="stop_input").count(),1);
    Lab::call(&l.a,json!({"op":"stop","session_id":id}));l.pump();assert_eq!(l.a_events.iter().filter(|e|e["event"]=="stop_input").count(),1);
}
#[test] fn focus_loss_requires_explicit_new_context_before_retry() {
    let mut l=Lab::new();l.pair();let id=l.local("apple_local");l.apple(&id,0,10,"pending");
    Lab::call(&l.b,json!({"op":"focus_invalid","session_id":id}));l.pump();assert_eq!(l.injections(),1);
    Lab::call(&l.b,json!({"op":"resume","session_id":id,"context_token":Uuid::new_v4(),"target_app":"TextEdit"}));l.pump();
    assert_eq!(l.injections(),2);l.apply(&id,1,"applied");
}
#[test] fn finalization_timeout_retains_draft_without_premature_send() {
    let mut l=Lab::new();l.pair();let id=l.local("apple_local");
    Lab::call(&l.a,json!({"op":"apple_result","session_id":id,"start":0,"end":10,"finalized_until":0,"text":"未确定尾部"}));
    Lab::call(&l.a,json!({"op":"stop","session_id":id}));std::thread::sleep(Duration::from_millis(1100));Lab::call(&l.a,json!({"op":"tick"}));l.pump();
    assert_eq!(l.injections(),0);assert_eq!(Lab::last(&l.a_events,&id)["draft"],"未确定尾部");assert_eq!(Lab::last(&l.a_events,&id)["phase"],"awaiting_confirmation");
}
#[test] fn active_session_prevents_target_or_mode_switch() {
    let mut l=Lab::new();l.pair();let _id=l.local("apple_local");
    assert!(l.a.dispatch(json!({"op":"begin","peer_id":l.b.device_id().unwrap(),"mode":"doubao_ime","remote":false}).to_string()).is_err());
}
