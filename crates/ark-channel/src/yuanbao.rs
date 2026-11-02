//! Tencent Yuanbao (元宝) bots (ported from Hermes `plugins/platforms/yuanbao`, MIT).
//!
//! Auth: `POST {api}/api/v5/robotLogic/sign-token` with an HMAC-SHA256 signature over
//! nonce + Beijing timestamp + app key + secret; the token is cached until a minute
//! before it expires and force-refreshed on every reconnect.
//! Transport: one WebSocket where every binary frame is a hand-written protobuf
//! `ConnMsg{Head head=1; bytes data=2}` (see [`proto`]): AUTH_BIND → BIND_ACK
//! (connectId), `ping` every 30 s (two missed pongs → reconnect), push ACKs when
//! `need_ack`, exponential reconnect backoff (1 s … 60 s), permanent close codes stop.
//! Inbound: `InboundMessagePush` (protobuf or JSON) → C2C (`direct:<account>`) or group
//! (`group:<code>`) messages; text, images, files, @bot mentions (TIMCustomElem 1002),
//! quotes (cloud_custom_data), WeChat forwarded chat records; frames from one sender
//! inside the debounce window are merged; own messages and recalls are dropped.
//! Outbound: `send_c2c_message` / `send_group_message` biz requests answered by
//! Response frames with the same msg_id; @nickname → mention elements from the group
//! member list; images/files go through `genUploadInfo` + a COS PUT signed with the
//! temporary credentials (q-sign-algorithm=sha1); reply heartbeats act as typing.

use crate::http::{classify, Http, Payload};
use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use ark_core::Cancel;
use ark_net::crypto;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_WS_URL: &str = "wss://bot-wss.yuanbao.tencent.com/wss/connection";
pub const DEFAULT_API: &str = "https://bot.yuanbao.tencent.com";
pub const MAX_MESSAGE: usize = 4000;
const TOKEN_PATH: &str = "/api/v5/robotLogic/sign-token";
const UPLOAD_INFO_PATH: &str = "/api/resource/genUploadInfo";
const DOWNLOAD_PATH: &str = "/api/resource/v1/download";
const SIGN_RETRYABLE_CODE: i64 = 10099;
const SIGN_MAX_RETRIES: u32 = 3;
const MAX_RECONNECT_ATTEMPTS: u32 = 100;
const HEARTBEAT_TIMEOUT_THRESHOLD: u32 = 2;
/// Permanent errors: never reconnect.
const NO_RECONNECT_CLOSE_CODES: [u16; 6] = [4012, 4013, 4014, 4018, 4019, 4021];
const MEDIA_MAX: usize = 50 * 1024 * 1024;
const MEMBER_CACHE_TTL: Duration = Duration::from_secs(300);
const RECALL_COMMANDS: [&str; 2] = ["Group.CallbackAfterRecallMsg", "C2C.CallbackAfterMsgWithDraw"];

/// Hand-written protobuf wire format for the Yuanbao gateway (port of `yuanbao_proto.py`).
pub mod proto {
    use std::sync::atomic::{AtomicU32, Ordering};

    pub const CMD_REQUEST: u64 = 0;
    pub const CMD_RESPONSE: u64 = 1;
    pub const CMD_PUSH: u64 = 2;
    pub const CMD_PUSH_ACK: u64 = 3;
    pub const MODULE_CONN: &str = "conn_access";
    pub const BIZ_PKG: &str = "yuanbao_openclaw_proxy";
    pub const INSTANCE_ID: u32 = 17;
    pub const HEARTBEAT_RUNNING: u64 = 1;
    pub const HEARTBEAT_FINISH: u64 = 2;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// Increasing uint32 sequence number (wraps to 0).
    pub fn next_seq() -> u32 {
        SEQ.fetch_add(1, Ordering::SeqCst)
    }

    pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    pub fn varint(v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        put_varint(&mut o, v);
        o
    }

    pub fn get_varint(d: &[u8], pos: &mut usize) -> Option<u64> {
        let (mut r, mut shift) = (0u64, 0u32);
        loop {
            let b = *d.get(*pos)?;
            *pos += 1;
            if shift < 64 {
                r |= ((b & 0x7f) as u64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(r);
            }
            if shift >= 64 {
                return None;
            }
        }
    }

    /// Always-encoded string field.
    pub fn s(out: &mut Vec<u8>, f: u32, v: &str) {
        put_varint(out, ((f as u64) << 3) | 2);
        put_varint(out, v.len() as u64);
        out.extend_from_slice(v.as_bytes());
    }
    /// String field, skipped when empty.
    pub fn s_nz(out: &mut Vec<u8>, f: u32, v: &str) {
        if !v.is_empty() {
            s(out, f, v);
        }
    }
    /// Always-encoded varint field.
    pub fn v(out: &mut Vec<u8>, f: u32, n: u64) {
        put_varint(out, (f as u64) << 3);
        put_varint(out, n);
    }
    pub fn v_nz(out: &mut Vec<u8>, f: u32, n: u64) {
        if n != 0 {
            v(out, f, n);
        }
    }
    /// Always-encoded length-delimited (nested message / bytes) field.
    pub fn m(out: &mut Vec<u8>, f: u32, b: &[u8]) {
        put_varint(out, ((f as u64) << 3) | 2);
        put_varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }
    pub fn m_nz(out: &mut Vec<u8>, f: u32, b: &[u8]) {
        if !b.is_empty() {
            m(out, f, b);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Val {
        Var(u64),
        Bytes(Vec<u8>),
    }

    /// Parsed message: fields in wire order.
    #[derive(Debug, Clone, Default)]
    pub struct Fields(pub Vec<(u32, Val)>);

    impl Fields {
        pub fn parse(d: &[u8]) -> Option<Fields> {
            let mut out = Vec::new();
            let mut pos = 0;
            while pos < d.len() {
                let tag = get_varint(d, &mut pos)?;
                let (f, wt) = ((tag >> 3) as u32, tag & 7);
                let val = match wt {
                    0 => Val::Var(get_varint(d, &mut pos)?),
                    1 | 2 | 5 => {
                        let len = match wt {
                            2 => get_varint(d, &mut pos)? as usize,
                            1 => 8,
                            _ => 4,
                        };
                        let end = pos.checked_add(len)?;
                        // Python slices silently truncate; keep that tolerance.
                        let b = d[pos..end.min(d.len())].to_vec();
                        pos = end;
                        Val::Bytes(b)
                    }
                    _ => return None,
                };
                out.push((f, val));
            }
            Some(Fields(out))
        }
        fn first(&self, f: u32) -> Option<&Val> {
            self.0.iter().find(|(n, _)| *n == f).map(|(_, v)| v)
        }
        pub fn var(&self, f: u32) -> u64 {
            match self.first(f) {
                Some(Val::Var(n)) => *n,
                _ => 0,
            }
        }
        pub fn bytes(&self, f: u32) -> Vec<u8> {
            match self.first(f) {
                Some(Val::Bytes(b)) => b.clone(),
                _ => Vec::new(),
            }
        }
        pub fn str(&self, f: u32) -> String {
            String::from_utf8_lossy(&self.bytes(f)).into_owned()
        }
        pub fn all_bytes(&self, f: u32) -> Vec<Vec<u8>> {
            self.0
                .iter()
                .filter_map(|(n, v)| match v {
                    Val::Bytes(b) if *n == f => Some(b.clone()),
                    _ => None,
                })
                .collect()
        }
        pub fn repeated(&self, f: u32) -> Vec<Fields> {
            self.all_bytes(f).iter().map(|b| Fields::parse(b).unwrap_or_default()).collect()
        }
    }

    // ---- ConnMsg / Head

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Head {
        pub cmd_type: u64,
        pub cmd: String,
        pub seq_no: u64,
        pub msg_id: String,
        pub module: String,
        pub need_ack: bool,
        pub status: i64,
    }

    pub fn encode_head(h: &Head) -> Vec<u8> {
        let mut o = Vec::new();
        v_nz(&mut o, 1, h.cmd_type);
        s_nz(&mut o, 2, &h.cmd);
        v_nz(&mut o, 3, h.seq_no);
        s_nz(&mut o, 4, &h.msg_id);
        s_nz(&mut o, 5, &h.module);
        v_nz(&mut o, 6, h.need_ack as u64);
        v_nz(&mut o, 10, h.status as u64);
        o
    }

    pub fn decode_head(d: &[u8]) -> Option<Head> {
        let f = Fields::parse(d)?;
        Some(Head { cmd_type: f.var(1), cmd: f.str(2), seq_no: f.var(3), msg_id: f.str(4), module: f.str(5), need_ack: f.var(6) != 0, status: f.var(10) as i64 as i32 as i64 })
    }

    pub fn encode_conn_msg_full(cmd_type: u64, cmd: &str, seq_no: u32, msg_id: &str, module: &str, data: &[u8], need_ack: bool) -> Vec<u8> {
        let h = Head { cmd_type, cmd: cmd.into(), seq_no: seq_no as u64, msg_id: msg_id.into(), module: module.into(), need_ack, status: 0 };
        let mut o = Vec::new();
        m(&mut o, 1, &encode_head(&h));
        m_nz(&mut o, 2, data);
        o
    }

    pub fn encode_conn_msg(cmd_type: u64, seq_no: u32, data: &[u8]) -> Vec<u8> {
        encode_conn_msg_full(cmd_type, "", seq_no, "", "", data, false)
    }

    /// ConnMsg → (head, data).
    pub fn decode_conn_msg(d: &[u8]) -> Option<(Head, Vec<u8>)> {
        let f = Fields::parse(d)?;
        Some((decode_head(&f.bytes(1))?, f.bytes(2)))
    }

    fn conn_request(cmd_type: u64, cmd: &str, msg_id: &str, module: &str, data: &[u8]) -> Vec<u8> {
        encode_conn_msg_full(cmd_type, cmd, next_seq(), msg_id, module, data, false)
    }

    /// Wrap an encoded business body: head.cmd = method, head.module = service.
    pub fn encode_biz_msg(service: &str, method: &str, req_id: &str, body: &[u8]) -> Vec<u8> {
        conn_request(CMD_REQUEST, method, req_id, service, body)
    }

    /// Business request; `msg_id` empty → `<prefix>_<seq>`. Returns (frame, req_id).
    fn biz_request(method: &str, prefix: &str, body: &[u8], msg_id: &str) -> (Vec<u8>, String) {
        let id = if msg_id.is_empty() { format!("{prefix}_{}", next_seq()) } else { msg_id.to_string() };
        (encode_biz_msg(BIZ_PKG, method, &id, body), id)
    }

    // ---- MsgContent / MsgBodyElement

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ImageInfo {
        pub kind: u64,
        pub size: u64,
        pub width: u64,
        pub height: u64,
        pub url: String,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Content {
        pub text: String,
        pub uuid: String,
        pub data: String,
        pub desc: String,
        pub ext: String,
        pub sound: String,
        pub url: String,
        pub file_name: String,
        pub image_format: u64,
        pub index: u64,
        pub file_size: u64,
        pub image_info_array: Vec<ImageInfo>,
        pub ext_map: Vec<(String, String)>,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Elem {
        pub msg_type: String,
        pub content: Content,
    }

    impl Elem {
        pub fn text(t: &str) -> Elem {
            Elem { msg_type: "TIMTextElem".into(), content: Content { text: t.into(), ..Default::default() } }
        }
    }

    pub fn encode_content(c: &Content) -> Vec<u8> {
        let mut o = Vec::new();
        for (f, val) in [(1, &c.text), (2, &c.uuid), (4, &c.data), (5, &c.desc), (6, &c.ext), (7, &c.sound), (10, &c.url), (12, &c.file_name)] {
            s_nz(&mut o, f, val);
        }
        v_nz(&mut o, 3, c.image_format);
        v_nz(&mut o, 9, c.index);
        v_nz(&mut o, 11, c.file_size);
        for img in &c.image_info_array {
            let mut b = Vec::new();
            v_nz(&mut b, 1, img.kind);
            v_nz(&mut b, 2, img.size);
            v_nz(&mut b, 3, img.width);
            v_nz(&mut b, 4, img.height);
            s_nz(&mut b, 5, &img.url);
            m(&mut o, 8, &b);
        }
        for (k, val) in &c.ext_map {
            let mut b = Vec::new();
            s_nz(&mut b, 1, k);
            s_nz(&mut b, 2, val);
            m(&mut o, 999, &b);
        }
        o
    }

    pub fn decode_content(d: &[u8]) -> Content {
        let f = Fields::parse(d).unwrap_or_default();
        let images = f
            .repeated(8)
            .iter()
            .map(|i| ImageInfo { kind: i.var(1), size: i.var(2), width: i.var(3), height: i.var(4), url: i.str(5) })
            .filter(|i| *i != ImageInfo::default())
            .collect();
        let ext_map = f.repeated(999).iter().map(|e| (e.str(1), e.str(2))).filter(|(k, _)| !k.is_empty()).collect();
        Content {
            text: f.str(1),
            uuid: f.str(2),
            image_format: f.var(3),
            data: f.str(4),
            desc: f.str(5),
            ext: f.str(6),
            sound: f.str(7),
            index: f.var(9),
            url: f.str(10),
            file_size: f.var(11),
            file_name: f.str(12),
            image_info_array: images,
            ext_map,
        }
    }

    pub fn encode_elem(e: &Elem) -> Vec<u8> {
        let mut o = Vec::new();
        s_nz(&mut o, 1, &e.msg_type);
        m_nz(&mut o, 2, &encode_content(&e.content));
        o
    }

    pub fn decode_elem(d: &[u8]) -> Elem {
        let f = Fields::parse(d).unwrap_or_default();
        let c = f.bytes(2);
        Elem { msg_type: f.str(1), content: if c.is_empty() { Content::default() } else { decode_content(&c) } }
    }

    fn body(o: &mut Vec<u8>, f: u32, elems: &[Elem]) {
        for e in elems {
            m(o, f, &encode_elem(e));
        }
    }

    fn trace(o: &mut Vec<u8>, f: u32, trace_id: &str) {
        if !trace_id.is_empty() {
            let mut b = Vec::new();
            s(&mut b, 1, trace_id);
            m(o, f, &b);
        }
    }

    // ---- InboundMessagePush

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Push {
        pub callback_command: String,
        pub from_account: String,
        pub to_account: String,
        pub sender_nickname: String,
        pub group_id: String,
        pub group_code: String,
        pub group_name: String,
        pub msg_seq: u64,
        pub msg_random: u64,
        pub msg_time: u64,
        pub msg_key: String,
        pub msg_id: String,
        pub msg_body: Vec<Elem>,
        pub cloud_custom_data: String,
        pub event_time: u64,
        pub bot_owner_id: String,
        /// (msg_seq, msg_id) of recalled messages.
        pub recall_msg_seq_list: Vec<(u64, String)>,
        pub claw_msg_type: u64,
        pub private_from_group_code: String,
        pub trace_id: String,
    }

    pub fn decode_inbound_push(d: &[u8]) -> Option<Push> {
        let f = Fields::parse(d)?;
        let trace = f.bytes(20);
        Some(Push {
            callback_command: f.str(1),
            from_account: f.str(2),
            to_account: f.str(3),
            sender_nickname: f.str(4),
            group_id: f.str(5),
            group_code: f.str(6),
            group_name: f.str(7),
            msg_seq: f.var(8),
            msg_random: f.var(9),
            msg_time: f.var(10),
            msg_key: f.str(11),
            msg_id: f.str(12),
            msg_body: f.all_bytes(13).iter().map(|b| decode_elem(b)).collect(),
            cloud_custom_data: f.str(14),
            event_time: f.var(15),
            bot_owner_id: f.str(16),
            recall_msg_seq_list: f.repeated(17).iter().map(|r| (r.var(1), r.str(2))).collect(),
            claw_msg_type: f.var(18),
            private_from_group_code: f.str(19),
            trace_id: if trace.is_empty() { String::new() } else { Fields::parse(&trace).map(|t| t.str(1)).unwrap_or_default() },
        })
    }

    /// Inverse of `decode_inbound_push` (used by tests and fake servers).
    pub fn encode_inbound_push(p: &Push) -> Vec<u8> {
        let mut o = Vec::new();
        for (f, val) in [(1, &p.callback_command), (2, &p.from_account), (3, &p.to_account), (4, &p.sender_nickname), (5, &p.group_id), (6, &p.group_code), (7, &p.group_name)] {
            s_nz(&mut o, f, val);
        }
        v_nz(&mut o, 8, p.msg_seq);
        v_nz(&mut o, 9, p.msg_random);
        v_nz(&mut o, 10, p.msg_time);
        s_nz(&mut o, 11, &p.msg_key);
        s_nz(&mut o, 12, &p.msg_id);
        body(&mut o, 13, &p.msg_body);
        s_nz(&mut o, 14, &p.cloud_custom_data);
        v_nz(&mut o, 15, p.event_time);
        s_nz(&mut o, 16, &p.bot_owner_id);
        for (seq, id) in &p.recall_msg_seq_list {
            let mut b = Vec::new();
            v_nz(&mut b, 1, *seq);
            s_nz(&mut b, 2, id);
            m(&mut o, 17, &b);
        }
        v_nz(&mut o, 18, p.claw_msg_type);
        s_nz(&mut o, 19, &p.private_from_group_code);
        trace(&mut o, 20, &p.trace_id);
        o
    }

    // ---- ForwardMsgData (WeChat chat-history forwards, base64 in ext_map)

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Multimedia {
        pub kind: String,
        pub url: String,
        pub file_name: String,
        pub file_size: u64,
        pub media_id: String,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ForwardContent {
        /// 1 text, 2 multimedia, 3 nested forward.
        pub kind: u64,
        pub text: String,
        pub multimedia: Vec<Multimedia>,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ForwardMsg {
        pub sender: String,
        pub time: u64,
        pub plain_text: String,
        pub contents: Vec<ForwardContent>,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ForwardData {
        pub sub_type: u64,
        pub begin_time: u64,
        pub end_time: u64,
        pub nick_name: String,
        pub msg: Vec<ForwardMsg>,
    }

    pub fn decode_forward_msg_data(d: &[u8]) -> Option<ForwardData> {
        let f = Fields::parse(d)?;
        let msg = f
            .repeated(5)
            .iter()
            .map(|fm| ForwardMsg {
                sender: fm.str(1),
                time: fm.var(2),
                plain_text: fm.str(3),
                contents: fm
                    .repeated(4)
                    .iter()
                    .map(|c| ForwardContent {
                        kind: c.var(1),
                        text: c.str(2),
                        multimedia: c.repeated(3).iter().map(|mm| Multimedia { kind: mm.str(1), url: mm.str(2), file_name: mm.str(4), file_size: mm.var(5), media_id: mm.str(15) }).collect(),
                    })
                    .collect(),
            })
            .collect();
        Some(ForwardData { sub_type: f.var(1), begin_time: f.var(2), end_time: f.var(3), nick_name: f.str(4), msg })
    }

    // ---- Outbound requests. Each returns (frame, req_id).

    #[allow(clippy::too_many_arguments)]
    pub fn encode_send_c2c_message(to_account: &str, msg_body: &[Elem], from_account: &str, msg_id: &str, msg_random: u64, msg_seq: Option<u64>, group_code: &str, trace_id: &str) -> (Vec<u8>, String) {
        let mut o = Vec::new();
        s_nz(&mut o, 1, msg_id);
        s(&mut o, 2, to_account);
        s_nz(&mut o, 3, from_account);
        v_nz(&mut o, 4, msg_random);
        body(&mut o, 5, msg_body);
        s_nz(&mut o, 6, group_code);
        if let Some(n) = msg_seq {
            v(&mut o, 7, n);
        }
        trace(&mut o, 8, trace_id);
        biz_request("send_c2c_message", "c2c", &o, msg_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encode_send_group_message(group_code: &str, msg_body: &[Elem], from_account: &str, msg_id: &str, to_account: &str, random: &str, msg_seq: Option<u64>, ref_msg_id: &str, trace_id: &str) -> (Vec<u8>, String) {
        let mut o = Vec::new();
        s_nz(&mut o, 1, msg_id);
        s(&mut o, 2, group_code);
        s_nz(&mut o, 3, from_account);
        s_nz(&mut o, 4, to_account);
        s_nz(&mut o, 5, random);
        body(&mut o, 6, msg_body);
        s_nz(&mut o, 7, ref_msg_id);
        if let Some(n) = msg_seq {
            v(&mut o, 8, n);
        }
        trace(&mut o, 9, trace_id);
        biz_request("send_group_message", "grp", &o, msg_id)
    }

    /// AuthBindReq{1 biz_id, 2 AuthInfo{uid, source, token}, 3 DeviceInfo{1 app_version,
    /// 2 os, 10 instance_id, 24 bot_version}, 5 env_name}.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_auth_bind(biz_id: &str, uid: &str, source: &str, token: &str, msg_id: &str, app_version: &str, os: &str, bot_version: &str, route_env: &str) -> Vec<u8> {
        let mut dev = Vec::new();
        s_nz(&mut dev, 1, app_version);
        s_nz(&mut dev, 2, os);
        s(&mut dev, 10, &INSTANCE_ID.to_string());
        s_nz(&mut dev, 24, bot_version);
        let mut auth = Vec::new();
        s(&mut auth, 1, uid);
        s(&mut auth, 2, source);
        s(&mut auth, 3, token);
        let mut req = Vec::new();
        s(&mut req, 1, biz_id);
        m_nz(&mut req, 2, &auth);
        m_nz(&mut req, 3, &dev);
        s_nz(&mut req, 5, route_env);
        conn_request(CMD_REQUEST, "auth-bind", msg_id, MODULE_CONN, &req)
    }

    /// AuthBindRsp{1 code, 2 message, 3 connect_id} → Ok(connect_id) or Err((code, message)).
    pub fn decode_auth_bind_rsp(d: &[u8]) -> Result<String, (u64, String)> {
        let f = Fields::parse(d).ok_or((u64::MAX, "undecodable AuthBindRsp".to_string()))?;
        match f.var(1) {
            0 if !f.str(3).is_empty() => Ok(f.str(3)),
            0 => Err((0, "BIND_ACK missing connectId".into())),
            c => Err((c, f.str(2))),
        }
    }

    pub fn encode_ping(msg_id: &str) -> Vec<u8> {
        conn_request(CMD_REQUEST, "ping", msg_id, MODULE_CONN, &[])
    }

    /// Push ACK echoing the original head's cmd / msg_id / module.
    pub fn encode_push_ack(h: &Head) -> Vec<u8> {
        conn_request(CMD_PUSH_ACK, &h.cmd, &h.msg_id, &h.module, &[])
    }

    pub fn encode_send_private_heartbeat(from_account: &str, to_account: &str, heartbeat: u64) -> (Vec<u8>, String) {
        let mut o = Vec::new();
        s(&mut o, 1, from_account);
        s(&mut o, 2, to_account);
        v(&mut o, 3, heartbeat);
        biz_request("send_private_heartbeat", "hb_priv", &o, "")
    }

    pub fn encode_send_group_heartbeat(from_account: &str, group_code: &str, heartbeat: u64, send_time_ms: u64) -> (Vec<u8>, String) {
        let ts = if send_time_ms == 0 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) } else { send_time_ms };
        let mut o = Vec::new();
        s(&mut o, 1, from_account);
        s(&mut o, 2, "");
        s(&mut o, 3, group_code);
        v(&mut o, 4, ts);
        v(&mut o, 5, heartbeat);
        biz_request("send_group_heartbeat", "hb_grp", &o, "")
    }

    pub fn encode_query_group_info(group_code: &str) -> (Vec<u8>, String) {
        let mut o = Vec::new();
        s(&mut o, 1, group_code);
        biz_request("query_group_info", "qgi", &o, "")
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct GroupInfo {
        pub code: u64,
        pub message: String,
        pub group_name: String,
        pub owner_id: String,
        pub owner_nickname: String,
        pub member_count: u64,
    }

    pub fn decode_query_group_info_rsp(d: &[u8]) -> Option<GroupInfo> {
        let f = Fields::parse(d)?;
        let gi = Fields::parse(&f.bytes(3)).unwrap_or_default();
        Some(GroupInfo { code: f.var(1), message: f.str(2), group_name: gi.str(1), owner_id: gi.str(2), owner_nickname: gi.str(3), member_count: gi.var(4) })
    }

    pub fn encode_get_group_member_list(group_code: &str, offset: u64, limit: u64) -> (Vec<u8>, String) {
        let mut o = Vec::new();
        s(&mut o, 1, group_code);
        v_nz(&mut o, 2, offset);
        v(&mut o, 3, limit);
        biz_request("get_group_member_list", "gml", &o, "")
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Member {
        pub user_id: String,
        pub nickname: String,
        /// 0 member, 1 admin, 2 owner.
        pub role: u64,
        pub join_time: u64,
        pub name_card: String,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct MemberList {
        pub code: u64,
        pub message: String,
        pub members: Vec<Member>,
        pub next_offset: u64,
        pub is_complete: bool,
    }

    pub fn decode_get_group_member_list_rsp(d: &[u8]) -> Option<MemberList> {
        let f = Fields::parse(d)?;
        Some(MemberList {
            code: f.var(1),
            message: f.str(2),
            members: f.repeated(3).iter().map(|x| Member { user_id: x.str(1), nickname: x.str(2), role: x.var(3), join_time: x.var(4), name_card: x.str(5) }).collect(),
            next_offset: f.var(4),
            is_complete: f.var(5) != 0,
        })
    }
}

/// Built-in sticker catalogue (TIMFaceElem), ported from Hermes `yuanbao_sticker.py`
/// (itself from yuanbao-openclaw-plugin `builtin-stickers.json`): every sticker is in
/// package 1003, 128×128 png, so only (name, sticker_id, description) vary.
pub mod sticker {
    use super::proto::{Content, Elem};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Sticker {
        pub name: &'static str,
        pub id: &'static str,
        pub description: &'static str,
    }

    pub const PACKAGE_ID: &str = "1003";

    const fn s(name: &'static str, id: &'static str, description: &'static str) -> Sticker {
        Sticker { name, id, description }
    }

    pub const STICKERS: &[Sticker] = &[
        s("六六六", "278", "666 厉害 牛 棒 绝了 好强 awesome"),
        s("我想开了", "262", "想开 佛系 释怀 顿悟 看淡了 无所谓"),
        s("害羞", "130", "腼腆 不好意思 脸红 娇羞 羞涩 捂脸"),
        s("比心", "252", "笔芯 爱你 爱心手势 love heart 喜欢你"),
        s("委屈", "125", "难过 想哭 可怜巴巴 瘪嘴 受伤 被欺负"),
        s("亲亲", "146", "么么 mua 亲一下 kiss 飞吻 啵"),
        s("酷", "131", "帅 墨镜 cool 高冷 有型 swagger"),
        s("睡", "145", "睡觉 困 zzZ 打盹 躺平 休眠 sleepy"),
        s("发呆", "152", "懵 愣住 放空 呆滞 出神 脑子空白"),
        s("可怜", "157", "卖萌 求饶 委屈巴巴 弱小 拜托 眼巴巴"),
        s("摊手", "200", "无奈 没办法 耸肩 随便 那咋整 whatever"),
        s("头大", "213", "头疼 烦恼 郁闷 难搞 崩溃 一团乱"),
        s("吓", "256", "害怕 惊恐 震惊 吓一跳 恐怖 怂"),
        s("吐血", "203", "无语 崩溃 被雷 内伤 一口老血 屮"),
        s("哼", "185", "傲娇 生气 不满 撇嘴 不理 赌气"),
        s("嘿嘿", "220", "坏笑 猥琐笑 偷笑 憨笑 得意 你懂的"),
        s("头秃", "218", "程序员 加班 焦虑 没头发 秃了 肝爆"),
        s("暗中观察", "221", "窥屏 潜水 偷偷看 角落 围观 屏住呼吸"),
        s("我酸了", "224", "嫉妒 柠檬精 羡慕 吃柠檬 眼红 恰柠檬"),
        s("打call", "246", "应援 加油 支持 喝彩 助威 call"),
        s("庆祝", "251", "祝贺 开心 耶 party 胜利 干杯"),
        s("奋斗", "151", "努力 加油 拼搏 冲 干劲 卷起来"),
        s("惊讶", "143", "震惊 哇 不敢相信 OMG 居然 这么离谱"),
        s("疑问", "144", "问号 不懂 啥 为什么 啥情况 懵逼问"),
        s("仔细分析", "248", "思考 推敲 认真 研究 琢磨 让我想想"),
        s("撅嘴", "184", "嘟嘴 卖萌 不高兴 撒娇 嘴翘"),
        s("泪奔", "199", "大哭 伤心 破防 感动哭 泪流满面 呜呜"),
        s("尊嘟假嘟", "276", "真的假的 真假 可爱问 你骗我 是不是"),
        s("略略略", "113", "调皮 吐舌 不服 略 气死你 鬼脸"),
        s("困", "180", "想睡 倦 打哈欠 睁不开眼 好困啊 sleepy"),
        s("折磨", "181", "难受 痛苦 煎熬 蚌埠住了 受不了 要命"),
        s("抠鼻", "182", "不屑 无聊 淡定 无所谓 鄙视 挖鼻"),
        s("鼓掌", "183", "拍手 叫好 赞同 666 喝彩 掌声"),
        s("斜眼笑", "204", "滑稽 坏笑 doge 意味深长 阴阳怪气 嘿嘿嘿"),
        s("辣眼睛", "216", "看不下去 cringe 毁三观 太丑了 瞎了"),
        s("哦哟", "217", "惊讶 起哄 哇哦 有戏 不简单 哟"),
        s("吃瓜", "222", "围观 看戏 八卦 路人 看热闹 板凳"),
        s("狗头", "225", "doge 保命 开玩笑 滑稽 反讽 懂的都懂"),
        s("敬礼", "227", "salute 尊重 收到 遵命 致敬 报告"),
        s("哦", "231", "知道了 明白 敷衍 嗯 这样啊 收到"),
        s("拿到红包", "236", "红包 谢谢老板 发财 开心 抢到了 欧气"),
        s("牛吖", "239", "牛 厉害 强 666 佩服 大佬"),
        s("贴贴", "272", "抱抱 亲昵 蹭蹭 亲密 靠靠 撒娇贴"),
        s("爱心", "138", "心 love 喜欢你 红心 示爱 么么哒"),
        s("晚安", "170", "好梦 睡了 night 早点休息 安啦 moon"),
        s("太阳", "176", "晴天 早上好 阳光 morning 好天气 日"),
        s("柠檬", "266", "酸 嫉妒 柠檬精 羡慕 我酸 恰柠檬"),
        s("大冤种", "267", "倒霉 吃亏 自嘲 好心没好报 背锅 工具人"),
        s("吐了", "132", "恶心 yue 受不了 嫌弃 想吐 生理不适"),
        s("怒", "134", "生气 愤怒 火大 暴躁 气炸 怼"),
        s("玫瑰", "165", "花 示爱 表白 浪漫 送你花 情人节"),
        s("凋谢", "119", "花谢 失恋 难过 枯萎 心碎 凉了"),
        s("点赞", "159", "赞 认同 好棒 good like 大拇指 顶"),
        s("握手", "164", "合作 你好 商务 hello deal 成交 友好"),
        s("抱拳", "163", "谢谢 失敬 江湖 承让 拜托 有礼"),
        s("ok", "169", "好的 收到 没问题 okay 行 可以 懂了"),
        s("拳头", "174", "加油 干 冲 fight 力量 击拳 硬气"),
        s("鞭炮", "191", "过年 喜庆 爆竹 春节 噼里啪啦 红"),
        s("烟花", "258", "庆典 漂亮 新年 嘭 绽放 节日快乐"),
    ];

    pub fn by_id(id: &str) -> Option<&'static Sticker> {
        let id = id.trim();
        STICKERS.iter().find(|s| !id.is_empty() && s.id == id)
    }

    /// Exact name → name/query substring either way → description contains the query → best fuzzy score.
    pub fn by_name(name: &str) -> Option<&'static Sticker> {
        let q = name.trim();
        if q.is_empty() {
            return None;
        }
        STICKERS
            .iter()
            .find(|s| s.name == q)
            .or_else(|| STICKERS.iter().find(|s| s.name.contains(q) || q.contains(s.name)))
            .or_else(|| STICKERS.iter().find(|s| s.description.contains(q)))
            .or_else(|| search(q, 1).into_iter().next())
    }

    /// Name, numeric sticker_id, or nothing (→ the first sticker, upstream picks one at random).
    pub fn lookup(q: &str) -> Option<&'static Sticker> {
        let q = q.trim();
        if q.is_empty() {
            return STICKERS.first();
        }
        (if q.bytes().all(|b| b.is_ascii_digit()) { by_id(q) } else { None }).or_else(|| by_name(q))
    }

    /// NFKC for what matters here: full-width ASCII and the ideographic space fold, then lowercase.
    fn normalize(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                '\u{3000}' => ' ',
                '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
                c => c,
            })
            .collect::<String>()
            .trim()
            .to_lowercase()
    }

    fn compact(s: &str) -> Vec<char> {
        const PUNCT: &str = "-_·.,，。!！?？\"“”'‘’、/\\";
        normalize(s).chars().filter(|c| !c.is_whitespace() && !PUNCT.contains(*c)).collect()
    }

    fn char_hit_ratio(needle: &[char], hay: &[char]) -> f64 {
        if needle.is_empty() {
            return 0.0;
        }
        let mut pool: Vec<char> = hay.to_vec();
        let mut hits = 0;
        for c in needle {
            if let Some(i) = pool.iter().position(|x| x == c) {
                pool.swap_remove(i);
                hits += 1;
            }
        }
        hits as f64 / needle.len() as f64
    }

    fn bigram_jaccard(a: &[char], b: &[char]) -> f64 {
        if a.len() < 2 || b.len() < 2 {
            return 0.0;
        }
        let set = |x: &[char]| x.windows(2).map(|w| (w[0], w[1])).collect::<std::collections::HashSet<_>>();
        let (sa, sb) = (set(a), set(b));
        sa.intersection(&sb).count() as f64 / sa.union(&sb).count() as f64
    }

    fn subsequence_ratio(needle: &[char], hay: &[char]) -> f64 {
        if needle.is_empty() {
            return 0.0;
        }
        let mut j = 0;
        for c in hay {
            if j >= needle.len() {
                break;
            }
            if *c == needle[j] {
                j += 1;
            }
        }
        j as f64 / needle.len() as f64
    }

    fn score_field(hay: &str, query: &str) -> f64 {
        let (h, q) = (normalize(hay), normalize(query));
        if h.is_empty() || q.is_empty() {
            return 0.0;
        }
        let (hc, qc) = (compact(hay), compact(query));
        let qn = q.chars().count();
        let qcs: String = qc.iter().collect();
        let hcs: String = hc.iter().collect();
        [
            if h == q { 100.0 } else { 0.0 },
            if h.contains(&q) { 92.0 + qn.min(6) as f64 } else { 0.0 },
            if qn >= 2 && h.starts_with(&q) { 88.0 } else { 0.0 },
            if !qc.is_empty() && hcs.contains(&qcs) { 86.0 } else { 0.0 },
            char_hit_ratio(&qc, &hc) * 62.0,
            bigram_jaccard(&qc, &hc) * 58.0,
            subsequence_ratio(&qc, &hc) * 52.0,
            if qn == 1 && h.contains(&q) { 68.0 } else { 0.0 },
        ]
        .into_iter()
        .fold(0.0, f64::max)
    }

    /// Fuzzy ranking as upstream `search_stickers`: name beats description (×0.88), sticker_id hits
    /// count too, and a floor relative to the best score drops the noise. Empty query → table order.
    pub fn search(query: &str, limit: usize) -> Vec<&'static Sticker> {
        let limit = limit.clamp(1, 500);
        let qn = normalize(query);
        if qn.is_empty() {
            return STICKERS.iter().take(limit).collect();
        }
        let mut scored: Vec<(f64, &'static Sticker)> = STICKERS
            .iter()
            .map(|s| {
                let id = normalize(s.id);
                let id_s = if id == qn { 100.0 } else if id.contains(&qn) { 84.0 } else { 0.0 };
                (score_field(s.name, query).max(score_field(s.description, query) * 0.88).max(id_s), s)
            })
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let top = scored.first().map(|x| x.0).unwrap_or(0.0);
        if top <= 0.0 {
            return scored.into_iter().take(limit).map(|x| x.1).collect();
        }
        let floor = if top >= 22.0 { 18.0 } else if top >= 12.0 { (top * 0.5).max(10.0) } else { (top * 0.35).max(6.0) };
        scored.into_iter().filter(|x| x.0 >= floor).take(limit).map(|x| x.1).collect()
    }

    /// `TIMFaceElem` with index 0 and the sticker metadata in `data` (same JSON as the JS plugin).
    pub fn elem(s: &Sticker) -> Elem {
        let data = serde_json::json!({"sticker_id": s.id, "package_id": PACKAGE_ID, "width": 128, "height": 128, "formats": "png", "name": s.name});
        Elem { msg_type: "TIMFaceElem".into(), content: Content { index: 0, data: data.to_string(), ..Default::default() } }
    }

    /// A text line that is only `[sticker: X]` / `[emoji: X]` naming a catalogue sticker exactly
    /// (name or id) — the form inbound stickers are rendered in, so the model can answer in kind.
    pub fn from_marker(line: &str) -> Option<&'static Sticker> {
        let l = line.trim();
        let inner = l.strip_prefix('[')?.strip_suffix(']')?;
        let (tag, v) = inner.split_once(':')?;
        if !matches!(tag.trim(), "sticker" | "emoji" | "表情" | "贴纸") {
            return None;
        }
        let v = v.trim();
        STICKERS.iter().find(|s| s.name == v || s.id == v)
    }
}

use proto::{Elem, Head, Push};

// ---------------------------------------------------------------- helpers

/// Beijing-time ISO-8601 without milliseconds: `2006-01-02T15:04:05+08:00`.
fn beijing_timestamp(unix: i64) -> String {
    let t = unix + 8 * 3600;
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}+08:00", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// HMAC-SHA256(key = secret, msg = nonce + timestamp + app_key + secret), hex.
pub fn sign_token_signature(nonce: &str, timestamp: &str, app_key: &str, app_secret: &str) -> String {
    crypto::hex(&crypto::hmac_sha256(app_secret.as_bytes(), format!("{nonce}{timestamp}{app_key}{app_secret}").as_bytes()))
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn uuid4() -> String {
    let mut b = crypto::random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crypto::hex(&b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        o => o,
    }
}

/// Python `urllib.parse.quote(s, safe=…)`.
fn quote(s: &str, safe: &[u8]) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || safe.contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// MD5 (RFC 1321) — the TIM image/file uuid is the content's MD5 hex.
pub fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in msg.chunks(64) {
        let w: Vec<u32> = chunk.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(w[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = Vec::new();
    for x in [a0, b0, c0, d0] {
        out.extend_from_slice(&x.to_le_bytes());
    }
    crypto::hex(&out)
}

fn hmac_sha1_hex(key: &str, msg: &str) -> String {
    crypto::hex(&crypto::hmac_sha1(key.as_bytes(), msg.as_bytes()))
}

/// COS `Authorization` header (q-sign-algorithm=sha1; cloud.tencent.com/document/product/436/7778).
#[allow(clippy::too_many_arguments)]
pub fn cos_sign(method: &str, path: &str, params: &[(&str, &str)], headers: &[(&str, &str)], secret_id: &str, secret_key: &str, start: i64, expire_secs: i64) -> String {
    let q_time = format!("{start};{}", start + expire_secs);
    let sign_key = hmac_sha1_hex(secret_key, &q_time);
    let sorted = |kv: &[(&str, &str)]| {
        let mut v: Vec<(String, String)> = kv.iter().map(|(k, v)| (k.to_lowercase(), quote(v, b""))).collect();
        v.sort();
        v
    };
    let (sp, sh) = (sorted(params), sorted(headers));
    let join = |p: &[(String, String)]| p.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let http_string = format!("{}\n{path}\n{}\n{}\n", method.to_lowercase(), join(&sp), join(&sh));
    let to_sign = format!("sha1\n{q_time}\n{}\n", crypto::hex(&crypto::sha1(http_string.as_bytes())));
    let keys = |p: &[(String, String)]| p.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    format!(
        "q-sign-algorithm=sha1&q-ak={secret_id}&q-sign-time={q_time}&q-key-time={q_time}&q-header-list={}&q-url-param-list={}&q-signature={}",
        keys(&sh),
        keys(&sp),
        hmac_sha1_hex(&sign_key, &to_sign)
    )
}

fn image_format(mime: &str) -> u64 {
    match mime.to_lowercase().as_str() {
        "image/jpeg" | "image/jpg" => 1,
        "image/gif" => 2,
        "image/png" => 3,
        "image/bmp" => 4,
        _ => 255,
    }
}

fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "heic" => "image/heic",
        "tiff" => "image/tiff",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "txt" => "text/plain",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

/// (width, height) of a PNG / JPEG / GIF / WebP image.
pub fn image_size(b: &[u8]) -> Option<(u64, u64)> {
    let be16 = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]) as u64;
    let le16 = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as u64;
    if b.len() >= 24 && b.starts_with(b"\x89PNG") {
        return Some((u32::from_be_bytes([b[16], b[17], b[18], b[19]]) as u64, u32::from_be_bytes([b[20], b[21], b[22], b[23]]) as u64));
    }
    if b.len() >= 4 && b.starts_with(&[0xff, 0xd8]) {
        let mut i = 2;
        while i + 9 < b.len() {
            if b[i] != 0xff {
                i += 1;
            } else if b[i + 1] == 0xc0 || b[i + 1] == 0xc2 {
                return Some((be16(i + 7), be16(i + 5)));
            } else {
                i += 2 + be16(i + 2) as usize;
            }
        }
        return None;
    }
    if b.len() >= 10 && (b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a")) {
        return Some((le16(6), le16(8)));
    }
    if b.len() >= 16 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        match &b[12..16] {
            b"VP8 " if b.len() >= 30 && b[23..26] == [0x9d, 0x01, 0x2a] => return Some((le16(26) & 0x3fff, le16(28) & 0x3fff)),
            b"VP8L" if b.len() >= 25 && b[20] == 0x2f => {
                let bits = u32::from_le_bytes([b[21], b[22], b[23], b[24]]) as u64;
                return Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1));
            }
            b"VP8X" if b.len() >= 30 => {
                let l24 = |i: usize| (b[i] as u64) | (b[i + 1] as u64) << 8 | (b[i + 2] as u64) << 16;
                return Some((l24(24) + 1, l24(27) + 1));
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------- inbound

/// `resourceId` from a Yuanbao resource URL's query string.
fn resource_id(url: &str) -> String {
    let q = url.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or("")).unwrap_or("");
    ark_net::parse_query(q).into_iter().find(|(k, _)| k == "resourceId" || k == "resourceid").map(|(_, v)| v.trim().to_string()).unwrap_or_default()
}

/// Medium image (index 1), else the first.
fn pick_image_url(c: &proto::Content) -> String {
    c.image_info_array.get(1).or_else(|| c.image_info_array.first()).map(|i| i.url.trim().to_string()).unwrap_or_default()
}

fn custom_json(e: &Elem) -> Option<Value> {
    (e.msg_type == "TIMCustomElem" && !e.content.data.is_empty()).then(|| serde_json::from_str(&e.content.data).ok()).flatten()
}

fn custom_elem_text(data: &str) -> String {
    const UNSUPPORTED: &str = "[unsupported message type]";
    if data.is_empty() {
        return UNSUPPORTED.into();
    }
    let Ok(c) = serde_json::from_str::<Value>(data) else { return data.to_string() };
    if !c.is_object() {
        return UNSUPPORTED.into();
    }
    match c["elem_type"].as_i64() {
        Some(1002) => c["text"].as_str().unwrap_or("[mention]").to_string(),
        Some(1009) => c["text"].as_str().unwrap_or("[chat record]").to_string(),
        Some(1010) => {
            let (title, link) = (c["title"].as_str().unwrap_or(""), c["link"].as_str().unwrap_or(""));
            let mut lines = vec![if link.is_empty() { format!("[share_card: {title}]") } else { format!("[share_card: {title} | {link}]") }];
            if let Some(p) = [&c["card_content"], &c["wechat_des"]].iter().find_map(|v| v.as_str().filter(|s| !s.is_empty())) {
                let short: String = p.chars().take(1000).collect();
                lines.push(format!("Preview: {}", if p.chars().count() > 1000 { format!("{short}...(truncated)") } else { short }));
            }
            if !link.is_empty() {
                lines.push("[visit link for full content]".into());
            }
            lines.join("\n")
        }
        Some(1007) => c["content"]
            .as_str()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|p| p["link"].as_str().map(|l| format!("[link: {l} | visit link for full content]")))
            .unwrap_or_else(|| UNSUPPORTED.into()),
        _ => UNSUPPORTED.into(),
    }
}

fn extract_text(body: &[Elem]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for e in body {
        let c = &e.content;
        match e.msg_type.as_str() {
            "TIMTextElem" => {
                if !c.text.is_empty() {
                    parts.push(c.text.clone());
                }
            }
            t @ ("TIMImageElem" | "TIMSoundElem" | "TIMVideoFileElem") => {
                let kind = match t {
                    "TIMImageElem" => "image",
                    "TIMSoundElem" => "voice",
                    _ => "video",
                };
                let url = if kind == "image" { pick_image_url(c) } else { c.url.trim().to_string() };
                let rid = resource_id(&url);
                parts.push(if rid.is_empty() { format!("[{kind}]") } else { format!("[{kind}|ybres:{rid}]") });
            }
            "TIMFileElem" => {
                let rid = resource_id(c.url.trim());
                let f = &c.file_name;
                parts.push(match (rid.is_empty(), f.is_empty()) {
                    (false, false) => format!("[file:{f}|ybres:{rid}]"),
                    (false, true) => format!("[file|ybres:{rid}]"),
                    (true, false) => format!("[file: {f}]"),
                    (true, true) => "[file]".into(),
                });
            }
            "TIMCustomElem" => parts.push(custom_elem_text(&c.data)),
            "TIMFaceElem" => {
                let d = serde_json::from_str::<Value>(&c.data).unwrap_or(Value::Null);
                let mut name = d["name"].as_str().map(|s| s.trim().to_string()).unwrap_or_default();
                if name.is_empty() {
                    name = d["sticker_id"].as_str().and_then(sticker::by_id).map(|s| s.name.to_string()).unwrap_or_default();
                }
                parts.push(if name.is_empty() { "[emoji]".into() } else { format!("[emoji: {name}]") });
            }
            "" => {}
            other => parts.push(format!("[{other}]")),
        }
    }
    parts.join(" ")
}

fn media_refs(body: &[Elem]) -> Vec<Media> {
    let mut out = Vec::new();
    for e in body {
        let c = &e.content;
        match e.msg_type.as_str() {
            "TIMImageElem" => {
                let url = pick_image_url(c);
                if !url.is_empty() {
                    let rid = resource_id(&url);
                    out.push(Media { kind: MediaKind::Image, id: (!rid.is_empty()).then_some(rid), url: Some(url), name: c.uuid.clone(), ..Default::default() });
                }
            }
            "TIMFileElem" => {
                let url = c.url.trim().to_string();
                if !url.is_empty() {
                    let rid = resource_id(&url);
                    out.push(Media { kind: MediaKind::Document, id: (!rid.is_empty()).then_some(rid), mime: guess_mime(&c.file_name).into(), name: c.file_name.trim().to_string(), size: c.file_size, url: Some(url), ..Default::default() });
                }
            }
            _ => {}
        }
    }
    out
}

/// ForwardMsgData from an elem_type 1009 custom element (first `sub_type == 1` entry).
fn forwarded_records(body: &[Elem]) -> Option<proto::ForwardData> {
    for e in body {
        let Some(c) = custom_json(e) else { continue };
        if c["elem_type"].as_i64() != Some(1009) {
            continue;
        }
        for (k, v) in &e.content.ext_map {
            if !k.starts_with("wexin_forward_msg_") || v.is_empty() {
                continue;
            }
            if let Some(d) = crypto::b64_decode(v).and_then(|b| proto::decode_forward_msg_data(&b)) {
                if d.sub_type == 1 {
                    return Some(d);
                }
            }
        }
        return None;
    }
    None
}

fn forward_text(d: &proto::ForwardData, nickname: &str, raw_text: &str, media: &mut Vec<Media>) -> String {
    let mut lines = vec![format!("当前用户的昵称为{}", if nickname.is_empty() { "用户" } else { nickname }), "以下为用户的聊天记录".to_string()];
    for msg in &d.msg {
        let mut parts: Vec<String> = Vec::new();
        for c in &msg.contents {
            match c.kind {
                1 => parts.push(c.text.clone()),
                2 => {
                    for mm in &c.multimedia {
                        let rid = if mm.media_id.is_empty() { resource_id(&mm.url) } else { mm.media_id.clone() };
                        let kind = if mm.kind.is_empty() { "file" } else { mm.kind.as_str() };
                        if kind == "url" {
                            parts.push(format!("[link: {}]", mm.url));
                            continue;
                        }
                        let name = if mm.file_name.is_empty() { String::new() } else { format!(" {}", mm.file_name) };
                        parts.push(if rid.is_empty() { format!("[{kind}]{name}") } else { format!("[{kind}|ybres:{rid}]{name}") });
                        if !mm.url.is_empty() || !rid.is_empty() {
                            media.push(Media {
                                kind: if kind == "image" { MediaKind::Image } else if kind == "video" { MediaKind::Video } else { MediaKind::Document },
                                url: (!mm.url.is_empty()).then(|| mm.url.clone()),
                                id: (!rid.is_empty()).then_some(rid),
                                name: mm.file_name.clone(),
                                size: mm.file_size,
                                ..Default::default()
                            });
                        }
                    }
                }
                3 => parts.push("[嵌套聊天记录]".into()),
                _ if !msg.plain_text.is_empty() => parts.push(msg.plain_text.clone()),
                _ => {}
            }
        }
        let mut rendered = parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join("  ");
        if rendered.is_empty() {
            rendered = msg.plain_text.clone();
        }
        if rendered.chars().count() > 2000 {
            rendered = rendered.chars().take(2000).collect::<String>() + "…(已截断)";
        }
        lines.push(format!("{}：{rendered}", msg.sender));
    }
    let mut text = lines.join("\n");
    if !raw_text.trim().is_empty() {
        text.push_str(&format!("\n\n用户附言：{}", raw_text.trim()));
    }
    text
}

fn js(v: &Value, keys: &[&str]) -> String {
    keys.iter().find_map(|k| match &v[*k] {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
    .unwrap_or_default()
}

fn ju(v: &Value, keys: &[&str]) -> u64 {
    keys.iter().find_map(|k| v[*k].as_u64().or_else(|| v[*k].as_str().and_then(|s| s.parse().ok()))).unwrap_or(0)
}

fn json_content(c: &Value) -> proto::Content {
    let c = match c {
        Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!({"text": s})),
        v => v.clone(),
    };
    proto::Content {
        text: js(&c, &["text", "Text"]),
        uuid: js(&c, &["uuid", "UUID"]),
        data: js(&c, &["data", "Data"]),
        desc: js(&c, &["desc", "Desc"]),
        url: js(&c, &["url", "Url", "URL"]),
        file_name: js(&c, &["file_name", "fileName", "filename", "FileName"]),
        file_size: ju(&c, &["file_size", "fileSize", "FileSize"]),
        image_format: ju(&c, &["image_format", "ImageFormat"]),
        image_info_array: c
            .get("image_info_array")
            .or_else(|| c.get("ImageInfoArray"))
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|i| proto::ImageInfo { kind: ju(i, &["type", "Type"]), size: ju(i, &["size", "Size"]), width: ju(i, &["width", "Width"]), height: ju(i, &["height", "Height"]), url: js(i, &["url", "URL", "Url"]) }).collect())
            .unwrap_or_default(),
        ext_map: c.get("ext_map").and_then(Value::as_object).map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect()).unwrap_or_default(),
        ..Default::default()
    }
}

/// JSON push (callback format or Tencent IM PascalCase keys) → Push.
fn parse_json_push(v: &Value) -> Option<Push> {
    if !v.is_object() {
        return None;
    }
    let raw_body = v.get("msg_body").or_else(|| v.get("MsgBody")).and_then(Value::as_array).cloned().unwrap_or_default();
    let msg_body: Vec<Elem> = raw_body
        .iter()
        .filter(|i| i.is_object())
        .map(|i| Elem { msg_type: js(i, &["msg_type", "MsgType"]), content: json_content(i.get("msg_content").or_else(|| i.get("MsgContent")).unwrap_or(&Value::Null)) })
        .collect();
    let from = js(v, &["from_account", "From_Account"]);
    let cmd = js(v, &["callback_command", "CallbackCommand"]);
    if from.is_empty() && msg_body.is_empty() && cmd.is_empty() {
        return None;
    }
    Some(Push {
        callback_command: cmd,
        from_account: from,
        to_account: js(v, &["to_account", "To_Account"]),
        sender_nickname: js(v, &["sender_nickname", "nick_name"]),
        group_code: js(v, &["group_code", "GroupId", "group_id"]),
        group_name: js(v, &["group_name"]),
        msg_seq: ju(v, &["msg_seq", "MsgSeq"]),
        msg_time: ju(v, &["msg_time", "MsgTime"]),
        msg_id: js(v, &["msg_id", "msg_key", "MsgKey"]),
        msg_body,
        cloud_custom_data: js(v, &["cloud_custom_data", "CloudCustomData"]),
        bot_owner_id: js(v, &["bot_owner_id", "botOwnerId"]),
        recall_msg_seq_list: v["recall_msg_seq_list"].as_array().map(|a| a.iter().map(|r| (ju(r, &["msg_seq"]), js(r, &["msg_id"]))).collect()).unwrap_or_default(),
        private_from_group_code: js(v, &["private_from_group_code"]),
        trace_id: v["log_ext"]["trace_id"].as_str().unwrap_or("").to_string(),
        ..Default::default()
    })
}

/// One push frame's biz payload: JSON first, then protobuf.
fn decode_push(data: &[u8]) -> Option<Push> {
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        if v.is_object() {
            return parse_json_push(&v);
        }
    }
    let p = proto::decode_inbound_push(data)?;
    (p != Push::default()).then_some(p)
}

/// Merge debounced frames: later bodies are appended after a newline element.
fn merge(pushes: Vec<Push>) -> Option<Push> {
    let mut it = pushes.into_iter();
    let mut first = it.next()?;
    for p in it {
        if !p.msg_body.is_empty() {
            first.msg_body.push(Elem::text("\n"));
            first.msg_body.extend(p.msg_body);
        }
    }
    Some(first)
}

const PLACEHOLDERS: [&str; 8] = ["[image]", "[图片]", "[file]", "[文件]", "[video]", "[视频]", "[voice]", "[语音]"];

/// A (merged) push → Inbound. `None` for recalls, our own messages and empty placeholders.
fn inbound_of(channel: &str, p: &Push, bot_id: &str) -> Option<Inbound> {
    if RECALL_COMMANDS.contains(&p.callback_command.as_str()) {
        return None;
    }
    if !p.from_account.is_empty() && p.from_account == bot_id {
        return None;
    }
    let mut text = extract_text(&p.msg_body).trim().to_string();
    if let Some(rest) = text.strip_prefix('\u{ff0f}') {
        text = format!("/{rest}");
    }
    let mut media = media_refs(&p.msg_body);
    if let Some(fwd) = forwarded_records(&p.msg_body) {
        text = forward_text(&fwd, &p.sender_nickname, &text, &mut media);
    }
    if media.is_empty() && (text.is_empty() || PLACEHOLDERS.contains(&text.as_str())) {
        return None;
    }
    let group = !p.group_code.is_empty();
    let mentioned = group
        && !bot_id.is_empty()
        && p.msg_body.iter().filter_map(custom_json).any(|c| c["elem_type"].as_i64() == Some(1002) && c["user_id"].as_str() == Some(bot_id));
    let reply = serde_json::from_str::<Value>(&p.cloud_custom_data).ok().and_then(|v| {
        let q = v.get("quote").filter(|q| q.is_object())?;
        let id = js(q, &["id"]).trim().to_string();
        let desc = js(q, &["desc"]).trim().to_string();
        let sender = js(q, &["sender_nickname", "sender_id"]);
        if id.is_empty() && desc.is_empty() {
            return None;
        }
        Some(ReplyRef { id, text: desc, author: sender, is_own: !bot_id.is_empty() && q["sender_id"].as_str() == Some(bot_id) })
    });
    let message_id = [&p.msg_id, &p.msg_key].iter().find(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or_else(|| format!("{}:{}:{}", p.from_account, p.msg_seq, p.msg_random));
    Some(Inbound {
        channel: channel.to_string(),
        chat: if group { format!("group:{}", p.group_code) } else { format!("direct:{}", p.from_account) },
        chat_type: if group { ChatType::Group } else { ChatType::Direct },
        chat_name: if group { if p.group_name.is_empty() { p.group_code.clone() } else { p.group_name.clone() } } else { String::new() },
        sender: p.from_account.clone(),
        sender_name: p.sender_nickname.clone(),
        text,
        message_id,
        ts: p.msg_time as i64,
        media,
        mentioned,
        reply,
        ..Default::default()
    })
}

/// `@nickname` tokens → TIMCustomElem 1002 mentions using the member cache (`nick lower → (nick, uid)`).
fn body_with_mentions(text: &str, members: &HashMap<String, (String, String)>) -> Vec<Elem> {
    if members.is_empty() {
        return vec![Elem::text(text)];
    }
    let mut out = Vec::new();
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut last = 0;
    let mut i = 0;
    while i < chars.len() {
        let (pos, ch) = chars[i];
        let at_start = i == 0 || chars[i - 1].1.is_whitespace();
        if ch == '@' && at_start && i + 1 < chars.len() && !chars[i + 1].1.is_whitespace() {
            let mut j = i + 1;
            while j < chars.len() && !chars[j].1.is_whitespace() {
                j += 1;
            }
            let end = chars.get(j).map(|c| c.0).unwrap_or(text.len());
            let seg = text[last..pos].trim();
            if !seg.is_empty() {
                out.push(Elem::text(seg));
            }
            let nick = &text[chars[i + 1].0..end];
            match members.get(&nick.to_lowercase()) {
                Some((real, uid)) => out.push(Elem {
                    msg_type: "TIMCustomElem".into(),
                    content: proto::Content { data: json!({"elem_type": 1002, "text": format!("@{real}"), "user_id": uid}).to_string(), ..Default::default() },
                }),
                None => out.push(Elem::text(&format!("@{nick}"))),
            }
            last = end;
            i = j;
            continue;
        }
        i += 1;
    }
    let tail = text[last..].trim();
    if !tail.is_empty() {
        out.push(Elem::text(tail));
    }
    if out.is_empty() {
        out.push(Elem::text(text));
    }
    out
}

// ---------------------------------------------------------------- channel

/// Timing knobs (tests shrink them).
#[derive(Debug, Clone)]
pub struct Timing {
    pub heartbeat: Duration,
    pub pong_timeout: Duration,
    pub auth_timeout: Duration,
    pub send_timeout: Duration,
    /// First reconnect delay; doubles up to 60 s.
    pub reconnect_base: Duration,
    pub sign_retry_delay: Duration,
    /// Frames from one sender inside this window are merged into one message.
    pub debounce: Duration,
    /// How long `send` waits for the gateway to be connected.
    pub connect_wait: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            heartbeat: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(10),
            send_timeout: Duration::from_secs(30),
            reconnect_base: Duration::from_secs(1),
            sign_retry_delay: Duration::from_secs(1),
            debounce: Duration::from_millis(1500),
            connect_wait: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub app_key: String,
    pub app_secret: String,
    pub bot_id: Option<String>,
    pub ws_url: Option<String>,
    pub api_domain: Option<String>,
    pub route_env: Option<String>,
    /// Replaces `https://{bucket}.cos.accelerate.myqcloud.com` (tests, private COS endpoints).
    pub cos_base: Option<String>,
    pub poll_timeout_secs: u64,
    pub timing: Timing,
}

#[derive(Clone)]
struct Token {
    token: String,
    bot_id: String,
    source: String,
    expires: Instant,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token(bot_id={}, ***)", self.bot_id)
    }
}

/// nickname (lowercase) → (nickname, user_id).
type Members = HashMap<String, (String, String)>;
type Reply = Result<(Head, Vec<u8>), ChannelError>;

struct Inner {
    id: String,
    cfg: Config,
    api: String,
    ws_url: String,
    http: Http,
    token: Mutex<Option<Token>>,
    bot_id: Mutex<String>,
    /// Frames for the socket thread; `Some` while authenticated.
    out: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    pending: Mutex<HashMap<String, mpsc::Sender<Reply>>>,
    inbox: Mutex<mpsc::Sender<Inbound>>,
    fatal: Mutex<Option<ChannelError>>,
    stop: AtomicBool,
    started: AtomicBool,
    members: Mutex<HashMap<String, (Instant, Members)>>,
    /// C2C chats that started from a group: account → group_code (echoed on send).
    dm_group: Mutex<HashMap<String, String>>,
}

pub struct Yuanbao {
    inner: Arc<Inner>,
    rx: Mutex<mpsc::Receiver<Inbound>>,
}

enum End {
    Stop,
    Drop(String),
    Fatal(ChannelError),
}

impl Inner {
    fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Sign-token, cached until a minute before expiry; `force` re-signs.
    fn get_token(&self, force: bool) -> Result<Token, ChannelError> {
        if !force {
            if let Some(t) = self.token.lock().unwrap().clone() {
                if t.expires > Instant::now() {
                    return Ok(t);
                }
            }
        }
        let url = format!("{}{TOKEN_PATH}", self.api);
        let mut attempt = 0;
        loop {
            let nonce = crypto::hex(&crypto::random_bytes(16));
            let ts = beijing_timestamp(now_unix());
            let body = json!({"app_key": self.cfg.app_key, "nonce": nonce, "signature": sign_token_signature(&nonce, &ts, &self.cfg.app_key, &self.cfg.app_secret), "timestamp": ts});
            let v = Self::version();
            let mut hs: Vec<(&str, &str)> = vec![("X-AppVersion", v), ("X-OperationSystem", os_name()), ("X-Instance-Id", "17"), ("X-Bot-Version", v)];
            let env = self.cfg.route_env.clone().unwrap_or_default();
            if !env.is_empty() {
                hs.push(("X-Route-Env", &env));
            }
            let r = self.http.call("POST", &url, &hs, Payload::Json(&body))?;
            if r.status != 200 {
                return Err(classify(r.status, r.retry_after, "yuanbao sign-token", &r.body));
            }
            let res: Value = serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("sign-token: bad JSON ({e})")))?;
            let code = res["code"].as_i64().unwrap_or(-1);
            if code == 0 {
                let d = &res["data"];
                if !d.is_object() {
                    return Err(ChannelError::new(K::Protocol, "sign-token response missing data"));
                }
                let dur = d["duration"].as_u64().filter(|d| *d > 0).unwrap_or(3600);
                let t = Token {
                    token: d["token"].as_str().unwrap_or("").to_string(),
                    bot_id: js(d, &["bot_id"]),
                    source: d["source"].as_str().unwrap_or("").to_string(),
                    expires: Instant::now() + Duration::from_secs(dur.saturating_sub(60)),
                };
                if !t.bot_id.is_empty() {
                    *self.bot_id.lock().unwrap() = t.bot_id.clone();
                }
                *self.token.lock().unwrap() = Some(t.clone());
                return Ok(t);
            }
            if code != SIGN_RETRYABLE_CODE || attempt >= SIGN_MAX_RETRIES {
                let kind = if code == SIGN_RETRYABLE_CODE { K::Network } else { K::Auth };
                return Err(ChannelError::new(kind, format!("yuanbao sign-token rejected: code={code} msg={}", res["msg"].as_str().unwrap_or(""))));
            }
            attempt += 1;
            std::thread::sleep(self.cfg.timing.sign_retry_delay);
        }
    }

    fn bot_id(&self) -> String {
        self.bot_id.lock().unwrap().clone()
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Socket thread: connect, authenticate, run; reconnect with backoff.
    fn run(self: Arc<Self>) {
        let mut attempt: u32 = 0;
        while !self.stopped() {
            if attempt > 0 {
                let wait = (self.cfg.timing.reconnect_base * 2u32.saturating_pow(attempt - 1)).min(Duration::from_secs(60));
                let until = Instant::now() + wait;
                while Instant::now() < until && !self.stopped() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if self.stopped() {
                    break;
                }
            }
            match self.connect(attempt > 0) {
                Ok(ws) => {
                    match self.session(ws) {
                        End::Stop => break,
                        End::Fatal(e) => {
                            *self.fatal.lock().unwrap() = Some(e);
                            break;
                        }
                        End::Drop(_why) => attempt = 1,
                    }
                }
                Err(e) if e.kind == K::Auth || e.kind == K::Fatal => {
                    *self.fatal.lock().unwrap() = Some(e);
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > MAX_RECONNECT_ATTEMPTS {
                        *self.fatal.lock().unwrap() = Some(ChannelError::new(K::Network, format!("yuanbao: giving up after {MAX_RECONNECT_ATTEMPTS} reconnect attempts: {}", e.message)));
                        break;
                    }
                }
            }
        }
        *self.out.lock().unwrap() = None;
        self.pending.lock().unwrap().clear();
    }

    fn connect(&self, force_token: bool) -> Result<WebSocket<ark_net::Stream>, ChannelError> {
        let tok = self.get_token(force_token)?;
        let (mut ws, _) = WebSocket::connect(&self.ws_url, &[], Duration::from_secs(15)).map_err(|e| ChannelError::new(K::Network, format!("yuanbao gateway: {e}")))?;
        let uid = {
            let b = self.bot_id();
            if b.is_empty() {
                tok.bot_id.clone()
            } else {
                b
            }
        };
        let v = Self::version();
        let source = if tok.source.is_empty() { "bot" } else { tok.source.as_str() };
        let frame = proto::encode_auth_bind("ybBot", &uid, source, &tok.token, &uuid4(), v, os_name(), v, self.cfg.route_env.as_deref().unwrap_or(""));
        let net = |e: std::io::Error| ChannelError::new(K::Network, format!("yuanbao gateway: {e}"));
        ws.send(&Message::Binary(frame)).map_err(net)?;
        ws.set_read_timeout(Some(Duration::from_millis(100))).map_err(net)?;
        let deadline = Instant::now() + self.cfg.timing.auth_timeout;
        while Instant::now() < deadline {
            if self.stopped() {
                return Err(ChannelError::new(K::Network, "stopped"));
            }
            match ws.recv().map_err(net)? {
                Some(Message::Binary(b)) => {
                    let Some((h, data)) = proto::decode_conn_msg(&b) else { continue };
                    if h.cmd_type != proto::CMD_RESPONSE || h.cmd != "auth-bind" {
                        continue;
                    }
                    return match proto::decode_auth_bind_rsp(&data) {
                        Ok(_connect_id) => Ok(ws),
                        // Invalid credentials are not fixed by retrying with the same token; reconnect re-signs.
                        Err((code, msg)) => Err(ChannelError::new(K::Network, format!("yuanbao AUTH_BIND failed: code={code} {msg}"))),
                    };
                }
                Some(Message::Close(c)) => {
                    return Err(close_error(c));
                }
                _ => {}
            }
        }
        Err(ChannelError::new(K::Network, "yuanbao AUTH_BIND timeout"))
    }

    fn session(&self, mut ws: WebSocket<ark_net::Stream>) -> End {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        *self.out.lock().unwrap() = Some(tx);
        let t = self.cfg.timing.clone();
        let mut next_ping = Instant::now() + t.heartbeat;
        let mut awaiting: Option<Instant> = None;
        let mut misses = 0;
        // sender key → (deadline, frames)
        let mut buf: HashMap<String, (Instant, Vec<Push>)> = HashMap::new();
        let end = loop {
            if self.stopped() {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                break End::Stop;
            }
            let mut failed = None;
            while let Ok(f) = rx.try_recv() {
                if let Err(e) = ws.send(&Message::Binary(f)) {
                    failed = Some(e.to_string());
                    break;
                }
            }
            if let Some(e) = failed {
                break End::Drop(e);
            }
            let now = Instant::now();
            if awaiting.is_some_and(|d| now > d) {
                awaiting = None;
                misses += 1;
                if misses >= HEARTBEAT_TIMEOUT_THRESHOLD {
                    break End::Drop("heartbeat timeout".into());
                }
            }
            if now >= next_ping && awaiting.is_none() {
                if let Err(e) = ws.send(&Message::Binary(proto::encode_ping(&uuid4()))) {
                    break End::Drop(e.to_string());
                }
                awaiting = Some(now + t.pong_timeout);
                next_ping = now + t.heartbeat;
            }
            let due: Vec<String> = buf.iter().filter(|(_, (d, _))| *d <= now).map(|(k, _)| k.clone()).collect();
            for k in due {
                if let Some((_, frames)) = buf.remove(&k) {
                    self.dispatch(frames);
                }
            }
            match ws.recv() {
                Ok(None) | Ok(Some(Message::Text(_))) | Ok(Some(Message::Ping(_))) | Ok(Some(Message::Pong(_))) => {}
                Ok(Some(Message::Binary(b))) => {
                    let Some((h, data)) = proto::decode_conn_msg(&b) else { continue };
                    match h.cmd_type {
                        proto::CMD_RESPONSE => {
                            if h.cmd == "ping" {
                                awaiting = None;
                                misses = 0;
                            } else if let Some(w) = self.pending.lock().unwrap().remove(&h.msg_id) {
                                let _ = w.send(Ok((h, data)));
                            }
                        }
                        proto::CMD_PUSH => {
                            if h.need_ack {
                                if let Err(e) = ws.send(&Message::Binary(proto::encode_push_ack(&h))) {
                                    break End::Drop(e.to_string());
                                }
                            }
                            if let Some(w) = self.pending.lock().unwrap().remove(&h.msg_id) {
                                let _ = w.send(Ok((h, data)));
                                continue;
                            }
                            if h.cmd == "kickout" || data.is_empty() {
                                continue;
                            }
                            if let Some(p) = decode_push(&data) {
                                let key = format!("{}:{}", p.from_account, p.group_code);
                                let e = buf.entry(key).or_insert_with(|| (now, Vec::new()));
                                e.0 = Instant::now() + t.debounce;
                                e.1.push(p);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Some(Message::Close(c))) => {
                    let e = close_error(c);
                    break if e.kind == K::Auth { End::Fatal(e) } else { End::Drop(e.message) };
                }
                Err(e) => break End::Drop(e.to_string()),
            }
        };
        *self.out.lock().unwrap() = None;
        for (_, (_, frames)) in buf.drain() {
            self.dispatch(frames);
        }
        // Fail in-flight requests now rather than at their timeout.
        for (_, w) in self.pending.lock().unwrap().drain() {
            let _ = w.send(Err(ChannelError::new(K::Network, "yuanbao gateway disconnected")));
        }
        end
    }

    fn dispatch(&self, frames: Vec<Push>) {
        let Some(p) = merge(frames) else { return };
        if !p.private_from_group_code.is_empty() && p.group_code.is_empty() {
            self.dm_group.lock().unwrap().insert(p.from_account.clone(), p.private_from_group_code.clone());
        }
        if let Some(m) = inbound_of(&self.id, &p, &self.bot_id()) {
            let _ = self.inbox.lock().unwrap().send(m);
        }
    }

    /// Send a biz request frame and wait for the Response with `req_id`.
    fn request(&self, frame: Vec<u8>, req_id: &str) -> Result<(Head, Vec<u8>), ChannelError> {
        let until = Instant::now() + self.cfg.timing.connect_wait;
        let out = loop {
            if let Some(e) = self.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if let Some(o) = self.out.lock().unwrap().clone() {
                break o;
            }
            if Instant::now() >= until {
                return Err(ChannelError::new(K::Network, "yuanbao gateway not connected"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(req_id.to_string(), tx);
        if out.send(frame).is_err() {
            self.pending.lock().unwrap().remove(req_id);
            return Err(ChannelError::new(K::Network, "yuanbao gateway not connected"));
        }
        let r = rx.recv_timeout(self.cfg.timing.send_timeout);
        self.pending.lock().unwrap().remove(req_id);
        let (h, data) = match r {
            Ok(r) => r?,
            Err(_) => return Err(ChannelError::new(K::Network, format!("yuanbao {req_id}: no response within {:?}", self.cfg.timing.send_timeout))),
        };
        if h.status != 0 {
            return Err(ChannelError::new(K::Protocol, format!("yuanbao {}: status {}", h.cmd, h.status)));
        }
        if let Some(f) = proto::Fields::parse(&data) {
            let code = f.var(1);
            if code != 0 {
                return Err(ChannelError::new(K::Protocol, format!("yuanbao {}: code={code} {}", h.cmd, f.str(2))));
            }
        }
        Ok((h, data))
    }

    /// Fire-and-forget frame (reply heartbeats).
    fn fire(&self, frame: Vec<u8>) -> Result<(), ChannelError> {
        match self.out.lock().unwrap().as_ref() {
            Some(o) => o.send(frame).map_err(|_| ChannelError::new(K::Network, "yuanbao gateway not connected")),
            None => Err(ChannelError::new(K::Network, "yuanbao gateway not connected")),
        }
    }

    fn members(&self, group: &str) -> HashMap<String, (String, String)> {
        if let Some((at, m)) = self.members.lock().unwrap().get(group) {
            if at.elapsed() < MEMBER_CACHE_TTL {
                return m.clone();
            }
        }
        let (frame, id) = proto::encode_get_group_member_list(group, 0, 200);
        let map: HashMap<String, (String, String)> = match self.request(frame, &id) {
            Ok((_, data)) => proto::decode_get_group_member_list_rsp(&data)
                .map(|l| l.members.into_iter().filter(|m| !m.nickname.is_empty() && !m.user_id.is_empty()).map(|m| (m.nickname.to_lowercase(), (m.nickname, m.user_id))).collect())
                .unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        self.members.lock().unwrap().insert(group.to_string(), (Instant::now(), map.clone()));
        map
    }

    fn auth_headers(&self, tok: &Token) -> Vec<(String, String)> {
        let bot = if tok.bot_id.is_empty() { self.bot_id() } else { tok.bot_id.clone() };
        let bot = if bot.is_empty() { self.cfg.app_key.clone() } else { bot };
        let mut h = vec![("X-Token".to_string(), tok.token.clone()), ("X-ID".to_string(), bot), ("X-Source".to_string(), "web".to_string())];
        if let Some(e) = self.cfg.route_env.as_deref().filter(|e| !e.is_empty()) {
            h.push(("X-Route-Env".into(), e.into()));
        }
        h
    }

    /// genUploadInfo → signed COS PUT. Returns (url, size, width, height).
    fn upload(&self, bytes: &[u8], filename: &str, mime: &str) -> Result<(String, u64, u64, u64), ChannelError> {
        if bytes.is_empty() {
            return Err(ChannelError::new(K::Fatal, format!("empty file: {filename}")));
        }
        if bytes.len() > MEDIA_MAX {
            return Err(ChannelError::new(K::Fatal, format!("file too large: {filename} ({} bytes)", bytes.len())));
        }
        let tok = self.get_token(false)?;
        let hs = self.auth_headers(&tok);
        let hs: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let body = json!({"fileName": filename, "fileId": crypto::hex(&crypto::random_bytes(16)), "docFrom": "localDoc", "docOpenId": ""});
        let r = self.http.call("POST", &format!("{}{UPLOAD_INFO_PATH}", self.api), &hs, Payload::Json(&body))?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, "yuanbao genUploadInfo", &r.body));
        }
        let res: Value = serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("genUploadInfo: bad JSON ({e})")))?;
        if let Some(c) = res["code"].as_i64().filter(|c| *c != 0) {
            return Err(ChannelError::new(K::Protocol, format!("genUploadInfo failed: code={c} msg={}", res["msg"].as_str().unwrap_or(""))));
        }
        let d = if res["data"].is_object() { &res["data"] } else { &res };
        let (bucket, key) = (d["bucketName"].as_str().unwrap_or(""), d["location"].as_str().unwrap_or(""));
        let (sid, skey, stoken) = (d["encryptTmpSecretId"].as_str().unwrap_or(""), d["encryptTmpSecretKey"].as_str().unwrap_or(""), d["encryptToken"].as_str().unwrap_or(""));
        if bucket.is_empty() || key.is_empty() || sid.is_empty() || skey.is_empty() {
            return Err(ChannelError::new(K::Protocol, "genUploadInfo returned incomplete credentials"));
        }
        let encoded = quote(key, b"/");
        let encoded = encoded.trim_start_matches('/');
        let base = self.cfg.cos_base.clone().unwrap_or_else(|| format!("https://{bucket}.cos.accelerate.myqcloud.com"));
        let cos_url = format!("{}/{encoded}", base.trim_end_matches('/'));
        let host = ark_net::Url::parse(&cos_url).map(|u| u.host_header()).map_err(|e| ChannelError::new(K::Fatal, e))?;
        let ctype = if mime.is_empty() || mime == "application/octet-stream" {
            let g = guess_mime(filename);
            if g.starts_with("image/") {
                g
            } else {
                "application/octet-stream"
            }
        } else {
            mime
        };
        let now = now_unix();
        let start = d["startTime"].as_i64().filter(|s| *s > 0).unwrap_or(now);
        let expire = d["expiredTime"].as_i64().filter(|e| *e > now).map(|e| e - now).unwrap_or(3600);
        let auth = cos_sign("put", &format!("/{encoded}"), &[], &[("host", &host), ("content-type", ctype), ("x-cos-security-token", stoken)], sid, skey, start, expire);
        let put = Http::new(Duration::from_secs(120));
        let r = put.call("PUT", &cos_url, &[("Authorization", &auth), ("x-cos-security-token", stoken)], Payload::Raw(ctype, bytes))?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, "yuanbao COS upload", &r.body));
        }
        let url = d["resourceUrl"].as_str().filter(|s| !s.is_empty()).map(str::to_string).unwrap_or(cos_url);
        let (w, h) = if ctype.starts_with("image/") { image_size(bytes).unwrap_or((0, 0)) } else { (0, 0) };
        Ok((url, bytes.len() as u64, w, h))
    }

    /// `resourceId` → direct download URL (one 401 retry after a forced re-sign).
    fn resource_url(&self, rid: &str) -> Result<String, ChannelError> {
        let url = format!("{}{DOWNLOAD_PATH}?resourceId={}", self.api, ark_net::urlencode(rid));
        let mut tok = self.get_token(false)?;
        for attempt in 0..2 {
            let hs = self.auth_headers(&tok);
            let hs: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let r = self.http.call("GET", &url, &hs, Payload::None)?;
            if r.status == 401 && attempt == 0 {
                tok = self.get_token(true)?;
                continue;
            }
            if !(200..300).contains(&r.status) {
                return Err(classify(r.status, r.retry_after, "yuanbao resource download", &r.body));
            }
            let v: Value = serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("resource download: bad JSON ({e})")))?;
            if let Some(c) = v["code"].as_i64().filter(|c| *c != 0) {
                let kind = if c == 404 { K::NotFound } else { K::Protocol };
                return Err(ChannelError::new(kind, format!("resource download failed: code={c} msg={}", v["msg"].as_str().unwrap_or(""))));
            }
            let d = if v["data"].is_object() { &v["data"] } else { &v };
            return d["url"].as_str().or_else(|| d["realUrl"].as_str()).filter(|s| !s.is_empty()).map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "resource download missing url"));
        }
        Err(ChannelError::new(K::Auth, "yuanbao resource download: token rejected"))
    }
}

fn close_error(c: Option<(u16, String)>) -> ChannelError {
    match c {
        Some((code, reason)) if NO_RECONNECT_CLOSE_CODES.contains(&code) => ChannelError::new(K::Auth, format!("yuanbao gateway closed permanently: {code} {reason}")),
        Some((code, reason)) => ChannelError::new(K::Network, format!("yuanbao gateway closed: {code} {reason}")),
        None => ChannelError::new(K::Network, "yuanbao gateway closed"),
    }
}

impl Yuanbao {
    pub fn new(id: &str, cfg: Config) -> Result<Yuanbao, String> {
        if cfg.app_key.trim().is_empty() || cfg.app_secret.trim().is_empty() {
            return Err(format!("channel {id}: yuanbao needs app_id and app_secret"));
        }
        let (tx, rx) = mpsc::channel();
        let inner = Inner {
            id: id.to_string(),
            api: cfg.api_domain.clone().unwrap_or_else(|| DEFAULT_API.into()).trim_end_matches('/').to_string(),
            ws_url: cfg.ws_url.clone().unwrap_or_else(|| DEFAULT_WS_URL.into()).trim().to_string(),
            http: Http::new(Duration::from_secs(15)),
            token: Mutex::new(None),
            bot_id: Mutex::new(cfg.bot_id.clone().unwrap_or_default()),
            out: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            inbox: Mutex::new(tx),
            fatal: Mutex::new(None),
            stop: AtomicBool::new(false),
            started: AtomicBool::new(false),
            members: Mutex::new(HashMap::new()),
            dm_group: Mutex::new(HashMap::new()),
            cfg,
        };
        Ok(Yuanbao { inner: Arc::new(inner), rx: Mutex::new(rx) })
    }

    fn ensure_started(&self) {
        if !self.inner.started.swap(true, Ordering::SeqCst) {
            let i = self.inner.clone();
            std::thread::Builder::new().name(format!("yuanbao {}", i.id)).spawn(move || i.run()).expect("spawn yuanbao thread");
        }
    }

    fn send_body(&self, chat: &str, body: Vec<Elem>, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let bot = self.inner.bot_id();
        let (frame, id) = match chat.strip_prefix("group:") {
            Some(g) => proto::encode_send_group_message(g, &body, &bot, &format!("grp_{}", proto::next_seq()), "", "", None, reply_to.unwrap_or(""), ""),
            None => {
                let to = chat.strip_prefix("direct:").unwrap_or(chat);
                let group = self.inner.dm_group.lock().unwrap().get(to).cloned().unwrap_or_default();
                proto::encode_send_c2c_message(to, &body, &bot, &format!("c2c_{}", proto::next_seq()), 0, None, &group, "")
            }
        };
        self.inner.request(frame, &id).map(|_| id)
    }

    /// Text chunk with retry (1 s, 2 s backoff) on transient errors.
    fn send_text_chunk(&self, chat: &str, text: &str, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let mut attempt = 0;
        loop {
            let body = match chat.strip_prefix("group:") {
                Some(g) if text.contains('@') => body_with_mentions(text, &self.inner.members(g)),
                _ => vec![Elem::text(text)],
            };
            match self.send_body(chat, body, reply_to) {
                Ok(id) => return Ok(id),
                Err(e) if e.is_retryable() && attempt < 2 && self.inner.fatal.lock().unwrap().is_none() => {
                    std::thread::sleep(self.inner.cfg.timing.reconnect_base * 2u32.pow(attempt));
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn media_body(&self, m: &Media) -> Result<Vec<Elem>, ChannelError> {
        if m.kind == MediaKind::Sticker && m.path.is_none() && m.url.is_none() {
            // Catalogue sticker by id or name (TIMFaceElem, nothing to upload).
            let q = m.id.as_deref().filter(|i| !i.is_empty()).unwrap_or(&m.name);
            let s = sticker::lookup(q).ok_or_else(|| ChannelError::new(K::Fatal, format!("unknown yuanbao sticker {q:?}")))?;
            return Ok(vec![sticker::elem(s)]);
        }
        let (bytes, name) = match (&m.path, &m.url) {
            (Some(p), _) => {
                let b = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                (b, std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()))
            }
            (None, Some(u)) => {
                let b = crate::http::get_bytes(u, &[], MEDIA_MAX as u64)?;
                let base = u.split(['?', '#']).next().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
                (b, base)
            }
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let image = m.kind == MediaKind::Image || m.kind == MediaKind::Sticker || m.mime.starts_with("image/");
        let name = if !m.name.is_empty() {
            m.name.clone()
        } else if name.is_empty() {
            if image { "image.jpg".into() } else { "document".into() }
        } else {
            name
        };
        let mime = if m.mime.is_empty() { guess_mime(&name).to_string() } else { m.mime.clone() };
        let mime = if image && !mime.starts_with("image/") { "image/jpeg".to_string() } else { mime };
        let uuid = md5_hex(&bytes);
        let (url, size, w, h) = self.inner.upload(&bytes, &name, &mime)?;
        Ok(vec![if image {
            Elem {
                msg_type: "TIMImageElem".into(),
                content: proto::Content { uuid, image_format: image_format(&mime), image_info_array: vec![proto::ImageInfo { kind: 1, size, width: w, height: h, url }], ..Default::default() },
            }
        } else {
            Elem { msg_type: "TIMFileElem".into(), content: proto::Content { uuid, file_name: name, file_size: size, url, ..Default::default() } }
        }])
    }

    fn heartbeat(&self, chat: &str, val: u64) -> Result<(), ChannelError> {
        let bot = self.inner.bot_id();
        if bot.is_empty() {
            return Ok(());
        }
        let (frame, _) = match chat.strip_prefix("group:") {
            Some(g) => proto::encode_send_group_heartbeat(&bot, g, val, 0),
            None => proto::encode_send_private_heartbeat(&bot, chat.strip_prefix("direct:").unwrap_or(chat), val),
        };
        self.inner.fire(frame)
    }
}

impl Drop for Yuanbao {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

fn button_text(rows: &[Vec<crate::Button>]) -> String {
    let mut n = 0;
    let mut lines = Vec::new();
    for b in rows.iter().flatten() {
        n += 1;
        lines.push(match &b.url {
            Some(u) => format!("{n}. {}: {u}", b.label),
            None => format!("{n}. {}", b.label),
        });
    }
    lines.join("\n")
}

impl Channel for Yuanbao {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 0,
            edit: false,
            delete: false,
            typing: true,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_started();
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.inner.cfg.poll_timeout_secs.max(1));
        while !cancel.is_cancelled() && Instant::now() < until {
            if let Ok(m) = rx.recv_timeout(Duration::from_millis(50)) {
                let mut got = vec![m];
                got.extend(rx.try_iter());
                return Ok(got);
            }
            if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                return Err(e);
            }
        }
        Ok(vec![])
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        self.ensure_started();
        let mut sent = Sent::default();
        let mut text = out.text.clone();
        if !out.buttons.is_empty() {
            let opts = button_text(&out.buttons);
            text = if text.trim().is_empty() { opts } else { format!("{}\n\n{opts}", text.trim_end()) };
        }
        let mut reply = out.reply_to.as_deref();
        // Lines that are only `[sticker: 比心]` go out as native stickers, in place.
        let mut segs: Vec<Result<String, &'static sticker::Sticker>> = vec![];
        for line in text.split('\n') {
            match (sticker::from_marker(line), segs.last_mut()) {
                (Some(s), _) => segs.push(Err(s)),
                (None, Some(Ok(t))) => {
                    t.push('\n');
                    t.push_str(line);
                }
                (None, _) => segs.push(Ok(line.to_string())),
            }
        }
        let plain = segs.len() == 1 && segs[0].is_ok();
        let caption_fits = plain && out.media.len() == 1 && !text.trim().is_empty() && text.chars().count() <= MAX_MESSAGE;
        for m in &out.media {
            let mut body = self.media_body(m)?;
            if caption_fits {
                body.push(Elem::text(&text));
            }
            sent.ids.push(self.send_body(&out.chat, body, reply)?);
            reply = None;
        }
        if !caption_fits {
            for seg in segs {
                match seg {
                    Err(s) => {
                        sent.ids.push(self.send_body(&out.chat, vec![sticker::elem(s)], reply)?);
                        reply = None;
                    }
                    Ok(t) => {
                        for piece in crate::chunk::split(&t, MAX_MESSAGE, LenUnit::Chars) {
                            sent.ids.push(self.send_text_chunk(&out.chat, &piece, reply)?);
                            reply = None;
                        }
                    }
                }
            }
        }
        if !sent.ids.is_empty() {
            let _ = self.heartbeat(&out.chat, proto::HEARTBEAT_FINISH);
        }
        Ok(sent)
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        self.ensure_started();
        self.heartbeat(chat, proto::HEARTBEAT_RUNNING)
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = match (&m.id, &m.url) {
            (Some(rid), _) if !rid.is_empty() => self.inner.resource_url(rid)?,
            (_, Some(u)) => u.clone(),
            _ => return Err(ChannelError::new(K::Fatal, "yuanbao attachment without resource id or url")),
        };
        crate::http::get_bytes(&url, &[], MEDIA_MAX as u64)
    }

    fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    app_id: String,
    app_secret: String,
    #[serde(default)]
    bot_id: Option<String>,
    #[serde(default)]
    ws_url: Option<String>,
    #[serde(default)]
    api_domain: Option<String>,
    #[serde(default)]
    route_env: Option<String>,
    #[serde(default)]
    cos_base_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default)]
    debounce_ms: Option<u64>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let mut timing = Timing::default();
    if let Some(d) = st.debounce_ms {
        timing.debounce = Duration::from_millis(d);
    }
    let cfg = Config {
        app_key: ctx.secret("app_id", &st.app_id)?.trim().to_string(),
        app_secret: ctx.secret("app_secret", &st.app_secret)?.trim().to_string(),
        bot_id: st.bot_id.filter(|b| !b.is_empty()),
        ws_url: st.ws_url,
        api_domain: st.api_domain,
        route_env: st.route_env,
        cos_base: st.cos_base_url,
        poll_timeout_secs: st.poll_timeout_secs,
        timing,
    };
    Ok(Arc::new(Yuanbao::new(ctx.name, cfg)?))
}

#[cfg(test)]
mod tests {
    use super::proto::*;
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::net::{TcpListener, TcpStream};

    type Ws = WebSocket<TcpStream>;
    type Log = Arc<Mutex<Vec<(Head, Vec<u8>)>>>;

    fn fast() -> Timing {
        Timing {
            heartbeat: Duration::from_secs(60),
            pong_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(3),
            send_timeout: Duration::from_secs(3),
            reconnect_base: Duration::from_millis(20),
            sign_retry_delay: Duration::from_millis(5),
            debounce: Duration::from_millis(150),
            connect_wait: Duration::from_secs(5),
        }
    }

    fn yb(api: &str, ws: &str, timing: Timing) -> Yuanbao {
        Yuanbao::new("yb", Config { app_key: "AK".into(), app_secret: "SK".into(), ws_url: Some(ws.into()), api_domain: Some(api.into()), cos_base: Some(api.into()), poll_timeout_secs: 2, timing, ..Default::default() }).unwrap()
    }

    fn token_ok() -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"code": 0, "data": {"token": "TOK", "bot_id": "bot1", "duration": 3600, "source": "bot"}}).to_string())
    }

    fn api_server() -> FakeServer {
        FakeServer::start(|req, _| {
            if req.path.starts_with(TOKEN_PATH) {
                return token_ok();
            }
            if req.path.starts_with(UPLOAD_INFO_PATH) {
                return (200, vec![], json!({"code": 0, "data": {"bucketName": "bkt", "region": "ap-guangzhou", "location": "/up/a b.png", "encryptTmpSecretId": "SID", "encryptTmpSecretKey": "SKEY", "encryptToken": "STOK", "startTime": 1700000000, "expiredTime": 4100000000u64, "resourceUrl": "https://res.example/a.png"}}).to_string());
            }
            if req.path.starts_with(DOWNLOAD_PATH) {
                let u = req.header("host").unwrap_or("").to_string();
                return (200, vec![], json!({"code": 0, "data": {"url": format!("http://{u}/blob/R1")}}).to_string());
            }
            if req.path.starts_with("/blob/") {
                return (200, vec![], "BYTES".into());
            }
            (200, vec![], String::new())
        })
    }

    fn ws_server(handler: impl Fn(usize, Ws) + Send + Sync + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/wss/connection", l.local_addr().unwrap());
        let h = Arc::new(handler);
        std::thread::spawn(move || {
            for (i, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let h = h.clone();
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let (head, rest) = ark_net::ws::read_head(&mut s, 65536).unwrap();
                    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    let ws = WebSocket::accept(s, &head, rest).unwrap();
                    h(i, ws);
                });
            }
        });
        url
    }

    fn next(ws: &mut Ws, within: Duration) -> Option<(Head, Vec<u8>)> {
        let until = Instant::now() + within;
        while Instant::now() < until {
            match ws.recv() {
                Ok(Some(Message::Binary(b))) => return decode_conn_msg(&b),
                Ok(Some(Message::Close(_))) | Err(_) => return None,
                _ => {}
            }
        }
        None
    }

    fn respond(ws: &mut Ws, h: &Head, data: &[u8]) {
        let _ = ws.send(&Message::Binary(encode_conn_msg_full(CMD_RESPONSE, &h.cmd, 0, &h.msg_id, &h.module, data, false)));
    }

    fn push(ws: &mut Ws, msg_id: &str, data: &[u8], need_ack: bool) {
        ws.send(&Message::Binary(encode_conn_msg_full(CMD_PUSH, "inbound_message", 0, msg_id, BIZ_PKG, data, need_ack))).unwrap();
    }

    /// Read AUTH_BIND, answer BIND_ACK; returns the AuthBindReq fields.
    fn auth(ws: &mut Ws) -> Fields {
        let (h, data) = next(ws, Duration::from_secs(5)).expect("auth-bind frame");
        assert_eq!((h.cmd.as_str(), h.module.as_str(), h.cmd_type), ("auth-bind", MODULE_CONN, CMD_REQUEST));
        let mut rsp = Vec::new();
        v(&mut rsp, 1, 0);
        s(&mut rsp, 3, "conn-1");
        respond(ws, &h, &rsp);
        Fields::parse(&data).unwrap()
    }

    /// Log every frame; answer requests until the socket closes.
    fn serve(ws: &mut Ws, log: &Log, until: Instant) {
        while Instant::now() < until {
            match ws.recv() {
                Ok(Some(Message::Binary(b))) => {
                    let (h, data) = decode_conn_msg(&b).unwrap();
                    log.lock().unwrap().push((h.clone(), data));
                    if h.cmd_type != CMD_REQUEST {
                        continue;
                    }
                    let rsp = if h.cmd == "get_group_member_list" {
                        let mut mem = Vec::new();
                        s(&mut mem, 1, "u-bob");
                        s(&mut mem, 2, "Bob");
                        let mut r = Vec::new();
                        m(&mut r, 3, &mem);
                        v(&mut r, 5, 1);
                        r
                    } else {
                        Vec::new()
                    };
                    respond(ws, &h, &rsp);
                }
                Ok(Some(Message::Close(_))) | Err(_) => return,
                _ => {}
            }
        }
    }

    fn text_elem_push(from: &str, group: &str, id: &str, body: Vec<Elem>) -> Vec<u8> {
        encode_inbound_push(&Push { from_account: from.into(), group_code: group.into(), msg_id: id.into(), msg_seq: 7, msg_time: 1700000000, msg_body: body, sender_nickname: format!("{from}-nick"), ..Default::default() })
    }

    fn poll_n(y: &Yuanbao, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(8);
        while got.len() < n && Instant::now() < until {
            got.extend(y.poll(&Cancel::new()).unwrap());
        }
        got
    }

    // ---- protocol known answers (from Hermes tests/gateway/test_yuanbao_proto.py)

    #[test]
    fn proto_known_answer_vectors() {
        assert_eq!(varint(300), [0xac, 0x02]);
        let d = [0x00, 0xac, 0x02, 0x00];
        let mut pos = 1;
        assert_eq!((get_varint(&d, &mut pos), pos), (Some(300), 3));
        for n in [0u64, 1, 127, 128, 255, 300, 16383, 16384, 1 << 21, 1 << 28, u64::MAX] {
            let mut p = 0;
            assert_eq!(get_varint(&varint(n), &mut p), Some(n));
        }
        // ConnMsg{head{seq_no=1}}
        assert_eq!(encode_conn_msg(0, 1, &[]), [0x0a, 0x02, 0x18, 0x01]);
        let (h, data) = decode_conn_msg(&encode_conn_msg(0, 42, b"hello world")).unwrap();
        assert_eq!((h.cmd_type, h.seq_no, data.as_slice()), (0, 42, &b"hello world"[..]));
        // TIMTextElem{text="hi"}
        let mut want = vec![0x0a, 11];
        want.extend_from_slice(b"TIMTextElem");
        want.extend_from_slice(&[0x12, 4, 0x0a, 2, b'h', b'i']);
        assert_eq!(encode_elem(&Elem::text("hi")), want);
        assert_eq!(decode_elem(&want), Elem::text("hi"));
        // Biz round trip and response flag.
        let enc = encode_biz_msg("trpc.yuanbao.example", "/im/send_c2c_msg", "req-001", b"\x0a\x05hello");
        let (h, body) = decode_conn_msg(&enc).unwrap();
        assert_eq!((h.module.as_str(), h.cmd.as_str(), h.msg_id.as_str(), body.as_slice(), h.cmd_type), ("trpc.yuanbao.example", "/im/send_c2c_msg", "req-001", &b"\x0a\x05hello"[..], CMD_REQUEST));
        // Negative int32 status survives the 64-bit two's complement encoding.
        let mut hb = Vec::new();
        m(&mut hb, 1, &encode_head(&Head { cmd_type: 1, status: -3, ..Default::default() }));
        assert_eq!(decode_conn_msg(&hb).unwrap().0.status, -3);
        // Hand-built InboundMessagePush (field order as in the proto).
        let mut buf = Vec::new();
        s(&mut buf, 2, "alice");
        s(&mut buf, 3, "bot");
        v(&mut buf, 8, 100);
        s(&mut buf, 11, "k001");
        m(&mut buf, 13, &encode_elem(&Elem::text("你好")));
        m(&mut buf, 13, &encode_elem(&Elem::text("part2")));
        let p = decode_inbound_push(&buf).unwrap();
        assert_eq!((p.from_account.as_str(), p.to_account.as_str(), p.msg_seq, p.msg_key.as_str()), ("alice", "bot", 100, "k001"));
        assert_eq!(p.msg_body, vec![Elem::text("你好"), Elem::text("part2")]);
        // Full push round trip incl. images, ext_map, recall list and trace id.
        let full = Push {
            callback_command: "Group.CallbackAfterRecallMsg".into(),
            group_code: "g".into(),
            recall_msg_seq_list: vec![(5, "m5".into())],
            trace_id: "tr".into(),
            msg_body: vec![Elem { msg_type: "TIMImageElem".into(), content: Content { uuid: "u".into(), image_format: 3, image_info_array: vec![ImageInfo { kind: 1, size: 9, width: 2, height: 3, url: "https://i".into() }], ext_map: vec![("k".into(), "v".into())], ..Default::default() } }],
            ..Default::default()
        };
        assert_eq!(decode_inbound_push(&encode_inbound_push(&full)).unwrap(), full);
        assert!(Fields::parse(&[0x0b]).is_none(), "wire type 3 rejected");
    }

    #[test]
    fn proto_requests_encode_expected_fields() {
        let (frame, id) = encode_send_c2c_message("alice", &[Elem::text("hi")], "bot1", "", 0, Some(0), "g9", "trace");
        assert!(id.starts_with("c2c_"));
        let (h, body) = decode_conn_msg(&frame).unwrap();
        assert_eq!((h.cmd.as_str(), h.module.as_str(), h.msg_id.as_str()), ("send_c2c_message", BIZ_PKG, id.as_str()));
        let f = Fields::parse(&body).unwrap();
        assert_eq!((f.str(1), f.str(2), f.str(3), f.str(6)), (String::new(), "alice".to_string(), "bot1".to_string(), "g9".to_string()));
        assert!(f.0.iter().any(|(n, v)| *n == 7 && *v == Val::Var(0)), "msg_seq Some(0) is still encoded");
        assert_eq!(Fields::parse(&f.bytes(8)).unwrap().str(1), "trace");
        assert_eq!(decode_elem(&f.bytes(5)), Elem::text("hi"));
        let (frame, _) = encode_send_group_message("g1", &[Elem::text("yo")], "bot1", "grp_x", "", "", None, "ref1", "");
        let (h, body) = decode_conn_msg(&frame).unwrap();
        let f = Fields::parse(&body).unwrap();
        assert_eq!((h.msg_id.as_str(), f.str(2), f.str(7)), ("grp_x", "g1".to_string(), "ref1".to_string()));
        let a = encode_auth_bind("ybBot", "bot1", "bot", "TOK", "mid", "1.0", "linux", "1.0", "");
        let (h, body) = decode_conn_msg(&a).unwrap();
        assert_eq!((h.cmd.as_str(), h.module.as_str(), h.msg_id.as_str()), ("auth-bind", "conn_access", "mid"));
        let f = Fields::parse(&body).unwrap();
        let ai = Fields::parse(&f.bytes(2)).unwrap();
        let dev = Fields::parse(&f.bytes(3)).unwrap();
        assert_eq!((f.str(1), ai.str(1), ai.str(2), ai.str(3), dev.str(10), dev.str(2)), ("ybBot".into(), "bot1".into(), "bot".into(), "TOK".into(), "17".into(), "linux".into()));
        let ack = encode_push_ack(&Head { cmd: "c".into(), msg_id: "m".into(), module: "mod".into(), ..Default::default() });
        let (h, _) = decode_conn_msg(&ack).unwrap();
        assert_eq!((h.cmd_type, h.cmd.as_str(), h.msg_id.as_str(), h.module.as_str()), (CMD_PUSH_ACK, "c", "m", "mod"));
        let (hb, _) = encode_send_group_heartbeat("bot1", "g1", HEARTBEAT_RUNNING, 123);
        let f = Fields::parse(&decode_conn_msg(&hb).unwrap().1).unwrap();
        assert_eq!((f.str(1), f.str(3), f.var(4), f.var(5)), ("bot1".into(), "g1".into(), 123, 1));
        assert!(f.0.iter().any(|(n, v)| *n == 2 && *v == Val::Bytes(vec![])), "empty to_account is encoded");
        // Group info / member list responses.
        let mut gi = Vec::new();
        s(&mut gi, 1, "Team");
        s(&mut gi, 2, "owner");
        v(&mut gi, 4, 12);
        let mut r = Vec::new();
        v(&mut r, 1, 0);
        m(&mut r, 3, &gi);
        assert_eq!(decode_query_group_info_rsp(&r).unwrap(), GroupInfo { group_name: "Team".into(), owner_id: "owner".into(), member_count: 12, ..Default::default() });
        let mut mem = Vec::new();
        s(&mut mem, 1, "u1");
        s(&mut mem, 2, "Amy");
        v(&mut mem, 3, 2);
        let mut r = Vec::new();
        m(&mut r, 3, &mem);
        v(&mut r, 4, 200);
        let l = decode_get_group_member_list_rsp(&r).unwrap();
        assert_eq!((l.members[0].nickname.as_str(), l.members[0].role, l.next_offset, l.is_complete), ("Amy", 2, 200, false));
        let (q, _) = encode_get_group_member_list("g", 0, 200);
        let f = Fields::parse(&decode_conn_msg(&q).unwrap().1).unwrap();
        assert_eq!((f.str(1), f.var(2), f.var(3)), ("g".into(), 0, 200));
    }

    #[test]
    fn crypto_and_helper_known_answers() {
        // openssl dgst -sha256 -hmac SK <<< "abc2024-01-02T03:04:05+08:00AKSK"
        assert_eq!(sign_token_signature("abc", "2024-01-02T03:04:05+08:00", "AK", "SK"), "e844c669235af6172560f8bc795c01109555ed949e72a15789cd7316d273786a");
        assert_eq!(beijing_timestamp(1704135845), "2024-01-02T03:04:05+08:00");
        assert_eq!(beijing_timestamp(0), "1970-01-01T08:00:00+08:00");
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(&[b'a'; 100]), "36a92cc94a9e0fa21f625f8bfb007adf");
        // COS signature, reference computed step by step with openssl.
        let a = cos_sign("PUT", "/a/b%20c.png", &[], &[("host", "bkt.cos.accelerate.myqcloud.com"), ("Content-Type", "image/png"), ("x-cos-security-token", "tok=1")], "SID", "SECRETKEY", 1700000000, 3600);
        assert_eq!(a, "q-sign-algorithm=sha1&q-ak=SID&q-sign-time=1700000000;1700003600&q-key-time=1700000000;1700003600&q-header-list=content-type;host;x-cos-security-token&q-url-param-list=&q-signature=e08b01649a0c4c6cdaa290d27bc24bb6a0d08f32");
        assert_eq!(quote("/up/a b+é.png", b"/"), "/up/a%20b%2B%C3%A9.png");
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 3]);
        assert_eq!(image_size(&png), Some((2, 3)));
        assert_eq!(image_size(b"GIF89a\x05\x00\x07\x00"), Some((5, 7)));
        let jpg = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0, 0, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x09, 0x00, 0x0b, 0x03, 0, 0];
        assert_eq!(image_size(&jpg), Some((11, 9)));
        assert_eq!(resource_id("https://x/api/resource/download?a=1&resourceId=R%201"), "R 1");
        assert_eq!(image_format("image/png"), 3);
        let u = uuid4();
        assert_eq!((u.len(), &u[14..15]), (36, "4"));
    }

    #[test]
    fn inbound_parsing_covers_kinds_mentions_quotes_forwards_and_drops() {
        let mention = |uid: &str| Elem { msg_type: "TIMCustomElem".into(), content: Content { data: json!({"elem_type": 1002, "text": "@bot", "user_id": uid}).to_string(), ..Default::default() } };
        let img = Elem { msg_type: "TIMImageElem".into(), content: Content { image_info_array: vec![ImageInfo { url: "https://a/orig".into(), ..Default::default() }, ImageInfo { url: "https://x/api/resource/download?resourceId=R1".into(), ..Default::default() }], ..Default::default() } };
        let p = Push { from_account: "bob".into(), group_code: "g1".into(), group_name: "Team".into(), msg_id: "m2".into(), msg_body: vec![mention("bot1"), Elem::text("look"), img], cloud_custom_data: json!({"quote": {"id": "q1", "desc": "earlier", "sender_id": "bot1"}}).to_string(), ..Default::default() };
        let m = inbound_of("yb", &p, "bot1").unwrap();
        assert_eq!((m.chat.as_str(), m.chat_type, m.chat_name.as_str(), m.text.as_str()), ("group:g1", ChatType::Group, "Team", "@bot look [image|ybres:R1]"));
        assert!(m.mentioned);
        assert_eq!((m.media[0].id.as_deref(), m.media[0].kind), (Some("R1"), MediaKind::Image));
        let r = m.reply.unwrap();
        assert!(r.is_own && r.id == "q1" && r.text == "earlier");
        let other = Push { msg_body: vec![mention("someone"), Elem::text("x")], ..p.clone() };
        assert!(!inbound_of("yb", &other, "bot1").unwrap().mentioned);
        assert!(inbound_of("yb", &Push { from_account: "bot1".into(), ..p.clone() }, "bot1").is_none(), "own message dropped");
        assert!(inbound_of("yb", &Push { callback_command: "C2C.CallbackAfterMsgWithDraw".into(), ..p.clone() }, "bot1").is_none(), "recall dropped");
        assert!(inbound_of("yb", &Push { from_account: "a".into(), msg_body: vec![Elem { msg_type: "TIMImageElem".into(), ..Default::default() }], ..Default::default() }, "bot1").is_none(), "bare [image] placeholder skipped");
        // DM with full-width slash command and a face.
        let dm = Push { from_account: "alice".into(), msg_key: "k1".into(), msg_body: vec![Elem::text("／new"), Elem { msg_type: "TIMFaceElem".into(), content: Content { data: r#"{"name":"smile"}"#.into(), ..Default::default() } }], ..Default::default() };
        let m = inbound_of("yb", &dm, "bot1").unwrap();
        assert_eq!((m.chat.as_str(), m.chat_type, m.text.as_str(), m.message_id.as_str()), ("direct:alice", ChatType::Direct, "/new [emoji: smile]", "k1"));
        // JSON push (Tencent IM PascalCase) with a file.
        let j = json!({"From_Account": "carol", "MsgKey": "m5", "MsgBody": [{"MsgType": "TIMFileElem", "MsgContent": {"url": "https://f/x.pdf", "fileName": "x.pdf", "file_size": 10}}]});
        let m = inbound_of("yb", &decode_push(j.to_string().as_bytes()).unwrap(), "bot1").unwrap();
        assert_eq!((m.sender.as_str(), m.message_id.as_str(), m.media[0].name.as_str(), m.media[0].size, m.media[0].mime.as_str()), ("carol", "m5", "x.pdf", 10, "application/pdf"));
        assert_eq!(m.text, "[file: x.pdf]");
        // Share card.
        let card = Elem { msg_type: "TIMCustomElem".into(), content: Content { data: json!({"elem_type": 1010, "title": "T", "link": "https://l"}).to_string(), ..Default::default() } };
        assert_eq!(extract_text(&[card]), "[share_card: T | https://l]\n[visit link for full content]");
        // WeChat forwarded chat records (ForwardMsgData protobuf, base64 in ext_map).
        let mut mc = Vec::new();
        v(&mut mc, 1, 1);
        s(&mut mc, 2, "hello there");
        let mut mm = Vec::new();
        s(&mut mm, 1, "image");
        s(&mut mm, 2, "https://img");
        s(&mut mm, 15, "MID");
        let mut mc2 = Vec::new();
        v(&mut mc2, 1, 2);
        proto::m(&mut mc2, 3, &mm);
        let mut fm = Vec::new();
        s(&mut fm, 1, "Ann");
        proto::m(&mut fm, 4, &mc);
        proto::m(&mut fm, 4, &mc2);
        let mut fd = Vec::new();
        v(&mut fd, 1, 1);
        s(&mut fd, 4, "fwd");
        proto::m(&mut fd, 5, &fm);
        let fwd = Elem { msg_type: "TIMCustomElem".into(), content: Content { data: json!({"elem_type": 1009, "text": "[chat record]"}).to_string(), ext_map: vec![("wexin_forward_msg_1_u".into(), crypto::b64(&fd))], ..Default::default() } };
        let m = inbound_of("yb", &Push { from_account: "dan".into(), sender_nickname: "Dan".into(), msg_id: "f1".into(), msg_body: vec![fwd], ..Default::default() }, "bot1").unwrap();
        assert!(m.text.contains("当前用户的昵称为Dan") && m.text.contains("Ann：hello there  [image|ybres:MID]"), "{}", m.text);
        assert_eq!(m.media[0].id.as_deref(), Some("MID"));
        // Merging debounced frames.
        let merged = merge(vec![Push { msg_body: vec![Elem::text("a")], ..Default::default() }, Push { msg_body: vec![Elem::text("b")], ..Default::default() }]).unwrap();
        assert_eq!(merged.msg_body, vec![Elem::text("a"), Elem::text("\n"), Elem::text("b")]);
        // @nickname → mention element.
        let mut mem = HashMap::new();
        mem.insert("bob".to_string(), ("Bob".to_string(), "u-bob".to_string()));
        let b = body_with_mentions("hi @bob there @nobody", &mem);
        assert_eq!(b.len(), 4);
        assert_eq!((b[0].content.text.as_str(), b[1].msg_type.as_str(), b[2].content.text.as_str(), b[3].content.text.as_str()), ("hi", "TIMCustomElem", "there", "@nobody"));
        assert!(b[1].content.data.contains("u-bob") && b[1].content.data.contains("@Bob"));
        assert_eq!(body_with_mentions("x@y", &mem), vec![Elem::text("x@y")]);
    }

    #[test]
    fn end_to_end_auth_push_ack_send_media_and_typing() {
        let api = api_server();
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let auths = Arc::new(Mutex::new(Vec::new()));
        let (l2, a2) = (log.clone(), auths.clone());
        let url = ws_server(move |_, mut ws| {
            let f = auth(&mut ws);
            let ai = Fields::parse(&f.bytes(2)).unwrap();
            a2.lock().unwrap().push((f.str(1), ai.str(1), ai.str(2), ai.str(3)));
            push(&mut ws, "p1", &text_elem_push("alice", "", "m1", vec![Elem::text("hello")]), true);
            push(&mut ws, "p2", &text_elem_push("bot1", "", "m-own", vec![Elem::text("echo")]), false);
            push(&mut ws, "p3", &json!({"from_account": "carol", "msg_id": "m5", "msg_body": [{"msg_type": "TIMFileElem", "msg_content": {"url": "https://f/x.pdf", "file_name": "x.pdf"}}]}).to_string().into_bytes(), false);
            // Two frames from one sender inside the debounce window → one message.
            push(&mut ws, "p4", &text_elem_push("dave", "g1", "m6", vec![Elem::text("part1")]), false);
            push(&mut ws, "p5", &text_elem_push("dave", "g1", "m7", vec![Elem::text("part2")]), false);
            serve(&mut ws, &l2, Instant::now() + Duration::from_secs(20));
        });
        let y = yb(&api.url, &url, fast());
        let got = poll_n(&y, 3);
        assert_eq!(got.len(), 3, "{got:?}");
        let by = |s: &str| got.iter().find(|m| m.sender == s).unwrap().clone();
        assert_eq!((by("alice").text.as_str(), by("alice").message_id.as_str(), by("alice").ts), ("hello", "m1", 1700000000));
        assert_eq!(by("carol").media[0].url.as_deref(), Some("https://f/x.pdf"));
        assert_eq!((by("dave").text.as_str(), by("dave").chat.as_str(), by("dave").message_id.as_str()), ("part1 \n part2", "group:g1", "m6"));
        assert!(got.iter().all(|m| m.sender != "bot1"));
        assert_eq!(auths.lock().unwrap()[0], ("ybBot".to_string(), "bot1".to_string(), "bot".to_string(), "TOK".to_string()));
        let tok_req = &api.requests()[0];
        let b = tok_req.json();
        assert_eq!((b["app_key"].as_str(), tok_req.header("X-Instance-Id")), (Some("AK"), Some("17")));
        assert_eq!(b["signature"].as_str().unwrap(), sign_token_signature(b["nonce"].as_str().unwrap(), b["timestamp"].as_str().unwrap(), "AK", "SK"));
        assert!(!b.to_string().contains("\"SK\""), "secret never sent");
        let acks: Vec<String> = log.lock().unwrap().iter().filter(|(h, _)| h.cmd_type == CMD_PUSH_ACK).map(|(h, _)| h.msg_id.clone()).collect();
        assert_eq!(acks, ["p1"], "only need_ack pushes are acknowledged");

        // C2C text with buttons (numbered fallback).
        let out = Outbound { buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }, crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://d".into()) }]], ..Outbound::text("direct:alice", "Pick one") };
        let sent = y.send(&out).unwrap();
        assert!(sent.ids[0].starts_with("c2c_"));
        let frames = || log.lock().unwrap().clone();
        let c2c = frames().into_iter().find(|(h, _)| h.cmd == "send_c2c_message").unwrap();
        assert_eq!(c2c.0.msg_id, sent.ids[0]);
        let f = Fields::parse(&c2c.1).unwrap();
        assert_eq!((f.str(2), f.str(3)), ("alice".into(), "bot1".into()));
        assert_eq!(decode_elem(&f.bytes(5)).content.text, "Pick one\n\n1. Yes\n2. Docs: https://d");
        let until = Instant::now() + Duration::from_secs(2);
        while !frames().iter().any(|(h, _)| h.cmd == "send_private_heartbeat") && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let hb = frames().into_iter().find(|(h, _)| h.cmd == "send_private_heartbeat").expect("FINISH heartbeat after delivery");
        assert_eq!(Fields::parse(&hb.1).unwrap().var(3), HEARTBEAT_FINISH);

        // Group reply with an @mention resolved through the member list.
        let sent = y.send(&Outbound { reply_to: Some("q1".into()), ..Outbound::text("group:g1", "hi @Bob there") }).unwrap();
        let grp = frames().into_iter().find(|(h, _)| h.cmd == "send_group_message" && h.msg_id == sent.ids[0]).unwrap();
        let f = Fields::parse(&grp.1).unwrap();
        assert_eq!((f.str(2), f.str(7)), ("g1".into(), "q1".into()));
        let body: Vec<Elem> = f.all_bytes(6).iter().map(|b| decode_elem(b)).collect();
        assert_eq!(body.len(), 3);
        assert!(body[1].content.data.contains("\"user_id\":\"u-bob\""));
        assert!(frames().iter().any(|(h, _)| h.cmd == "get_group_member_list"));

        // Local image → genUploadInfo + signed COS PUT → TIMImageElem with caption.
        let dir = temp_dir("yb");
        let p = dir.join("pic.png");
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 3]);
        std::fs::write(&p, &png).unwrap();
        let img = Media { kind: MediaKind::Image, path: Some(p.display().to_string()), ..Default::default() };
        let sent = y.send(&Outbound { media: vec![img], ..Outbound::text("direct:alice", "caption") }).unwrap();
        assert_eq!(sent.ids.len(), 1);
        let reqs = api.requests();
        let gen = reqs.iter().find(|r| r.path == UPLOAD_INFO_PATH).unwrap();
        assert_eq!((gen.header("X-Token"), gen.header("X-ID"), gen.header("X-Source"), gen.json()["fileName"].as_str()), (Some("TOK"), Some("bot1"), Some("web"), Some("pic.png")));
        let put = reqs.iter().find(|r| r.method == "PUT").unwrap();
        assert_eq!(put.path, "/up/a%20b.png");
        assert!(put.header("authorization").unwrap().starts_with("q-sign-algorithm=sha1&q-ak=SID&q-sign-time=1700000000;"));
        assert!(put.header("authorization").unwrap().contains("q-header-list=content-type;host;x-cos-security-token"));
        assert_eq!((put.header("x-cos-security-token"), put.header("content-type")), (Some("STOK"), Some("image/png")));
        let c2c = frames().into_iter().rfind(|(h, _)| h.cmd == "send_c2c_message").unwrap();
        let body: Vec<Elem> = Fields::parse(&c2c.1).unwrap().all_bytes(5).iter().map(|b| decode_elem(b)).collect();
        assert_eq!(body[0].msg_type, "TIMImageElem");
        let c = &body[0].content;
        assert_eq!((c.uuid.as_str(), c.image_format, c.image_info_array[0].url.as_str(), c.image_info_array[0].width, c.image_info_array[0].height), (md5_hex(&png).as_str(), 3, "https://res.example/a.png", 2, 3));
        assert_eq!(body[1], Elem::text("caption"));
        // A document goes out as TIMFileElem.
        let f = dir.join("r.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        y.send(&Outbound { media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("group:g1", "") }).unwrap();
        let grp = frames().into_iter().rfind(|(h, _)| h.cmd == "send_group_message").unwrap();
        let e = decode_elem(&Fields::parse(&grp.1).unwrap().bytes(6));
        assert_eq!((e.msg_type.as_str(), e.content.file_name.as_str(), e.content.file_size), ("TIMFileElem", "r.pdf", 4));

        // Stickers: a marker line becomes its own TIMFaceElem in order; a Sticker media by id too.
        let sent = y.send(&Outbound { media: vec![Media { kind: MediaKind::Sticker, id: Some("252".into()), ..Default::default() }], ..Outbound::text("direct:alice", "nice\n[sticker: 六六六]\nbye") }).unwrap();
        assert_eq!(sent.ids.len(), 4);
        let faces: Vec<Vec<Elem>> = sent.ids.iter().map(|id| frames().into_iter().find(|(h, _)| h.msg_id == *id).unwrap()).map(|(_, d)| Fields::parse(&d).unwrap().all_bytes(5).iter().map(|b| decode_elem(b)).collect()).collect();
        assert_eq!(faces[0][0].msg_type, "TIMFaceElem");
        assert!(faces[0][0].content.data.contains("\"sticker_id\":\"252\"") && faces[0][0].content.data.contains("\"name\":\"比心\""));
        assert_eq!((faces[1][0].content.text.as_str(), faces[3][0].content.text.as_str()), ("nice", "bye"));
        let v: Value = serde_json::from_str(&faces[2][0].content.data).unwrap();
        assert_eq!(v, json!({"sticker_id": "278", "package_id": "1003", "width": 128, "height": 128, "formats": "png", "name": "六六六"}));

        // Typing = RUNNING reply heartbeat; fetch_media resolves the resourceId.
        y.typing("group:g1", None).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let hbs: Vec<u64> = frames().into_iter().filter(|(h, _)| h.cmd == "send_group_heartbeat").map(|(_, d)| Fields::parse(&d).unwrap().var(5)).collect();
        assert_eq!(hbs.last(), Some(&HEARTBEAT_RUNNING), "{hbs:?}");
        let bytes = y.fetch_media(&Media { id: Some("R1".into()), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"BYTES");
        let dl = api.requests().into_iter().find(|r| r.path.starts_with(DOWNLOAD_PATH)).unwrap();
        assert_eq!((dl.path.as_str(), dl.header("X-Token")), ("/api/resource/v1/download?resourceId=R1", Some("TOK")));
        assert_eq!(api.requests().iter().filter(|r| r.path == TOKEN_PATH).count(), 1, "token cached: {:?}", api.requests().iter().map(|r| r.path.clone()).collect::<Vec<_>>());
        y.stop();
    }

    #[test]
    fn sticker_catalogue_lookup_and_search() {
        assert_eq!(sticker::STICKERS.len(), 59);
        assert_eq!(sticker::by_id("278").unwrap().name, "六六六");
        assert_eq!(sticker::lookup("252").unwrap().name, "比心");
        assert_eq!(sticker::by_name("比心").unwrap().id, "252");
        // Substring of a name, then description keyword.
        assert_eq!(sticker::by_name("暗中").unwrap().name, "暗中观察");
        assert_eq!(sticker::by_name("窥屏").unwrap().name, "暗中观察");
        assert_eq!(sticker::by_name("柠檬精").unwrap().name, "柠檬", "a name inside the query wins over descriptions");
        assert_eq!(sticker::search("doge", 2).iter().map(|s| s.name).collect::<Vec<_>>(), ["斜眼笑", "狗头"]);
        assert_eq!(sticker::search("ＯＫ", 1)[0].name, "ok", "full-width folds like NFKC");
        assert_eq!(sticker::search("", 3).len(), 3);
        assert_eq!(sticker::from_marker(" [emoji: 晚安] ").unwrap().id, "170");
        assert!(sticker::from_marker("[emoji: 晚安吧]").is_none() && sticker::from_marker("晚安").is_none());
        let p = Push { from_account: "a".into(), msg_body: vec![Elem { msg_type: "TIMFaceElem".into(), content: proto::Content { data: r#"{"sticker_id":"170"}"#.into(), ..Default::default() } }], ..Default::default() };
        assert_eq!(extract_text(&p.msg_body), "[emoji: 晚安]");
    }

    #[test]
    fn sign_token_errors_map_to_kinds() {
        let ws = "ws://127.0.0.1:1/x";
        // Rejected credentials → Auth, surfaced by poll, secret never echoed.
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"code": 40001, "msg": "invalid app_secret SK"}).to_string()));
        let y = yb(&srv.url, ws, fast());
        let start = Instant::now();
        let e = loop {
            match y.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) => assert!(start.elapsed() < Duration::from_secs(5)),
            }
        };
        assert_eq!(e.kind, K::Auth, "{e}");
        assert_eq!(y.send(&Outbound::text("direct:a", "x")).unwrap_err().kind, K::Auth);
        // Retryable code 10099 is retried, then succeeds.
        let srv = FakeServer::start(|_, n| if n == 0 { (200, vec![], json!({"code": 10099}).to_string()) } else { token_ok() });
        let y = yb(&srv.url, ws, fast());
        assert_eq!(y.inner.get_token(false).unwrap().token, "TOK");
        assert_eq!(srv.requests().len(), 2);
        assert_eq!(y.inner.bot_id(), "bot1", "bot id adopted from sign-token");
        // HTTP status mapping.
        for (status, kind) in [(429, K::RateLimited { retry_after: Some(Duration::from_secs(7)) }), (502, K::Network), (401, K::Auth)] {
            let srv = FakeServer::start(move |_, _| (status, vec![("Retry-After".into(), "7".into())], "{}".into()));
            let y = yb(&srv.url, ws, fast());
            assert_eq!(y.inner.get_token(false).unwrap_err().kind, kind, "{status}");
        }
    }

    #[test]
    fn biz_errors_timeouts_and_resource_lookups() {
        let failed_once = Arc::new(AtomicBool::new(false));
        let api = FakeServer::start(move |req, _| {
            if req.path.starts_with(TOKEN_PATH) {
                return token_ok();
            }
            if req.path.contains("resourceId=GONE") {
                return (200, vec![], json!({"code": 404, "msg": "not found"}).to_string());
            }
            if req.path.contains("resourceId=AUTH") && !failed_once.swap(true, Ordering::SeqCst) {
                return (401, vec![], String::new());
            }
            if req.path.contains("resourceId=SLOW") {
                return (429, vec![("Retry-After".into(), "3".into())], String::new());
            }
            (200, vec![], json!({"code": 0, "data": {"realUrl": "https://real/x"}}).to_string())
        });
        let url = ws_server(|_, mut ws| {
            auth(&mut ws);
            let until = Instant::now() + Duration::from_secs(20);
            while Instant::now() < until {
                let Some((h, data)) = next(&mut ws, Duration::from_millis(200)) else { continue };
                let to = Fields::parse(&data).map(|f| f.str(2)).unwrap_or_default();
                match to.as_str() {
                    "status" => {
                        let mut hb = Vec::new();
                        m(&mut hb, 1, &encode_head(&Head { cmd_type: CMD_RESPONSE, cmd: h.cmd.clone(), msg_id: h.msg_id.clone(), status: 5, ..Default::default() }));
                        ws.send(&Message::Binary(hb)).unwrap();
                    }
                    "code" => {
                        let mut r = Vec::new();
                        v(&mut r, 1, 20003);
                        s(&mut r, 2, "user not exist");
                        respond(&mut ws, &h, &r);
                    }
                    "silent" => {}
                    _ => respond(&mut ws, &h, &[]),
                }
            }
        });
        let mut t = fast();
        t.send_timeout = Duration::from_millis(300);
        let y = yb(&api.url, &url, t);
        assert_eq!(y.send(&Outbound::text("direct:status", "x")).unwrap_err().kind, K::Protocol);
        let e = y.send(&Outbound::text("direct:code", "x")).unwrap_err();
        assert!(e.kind == K::Protocol && e.message.contains("20003"), "{e}");
        let start = Instant::now();
        let e = y.send(&Outbound::text("direct:silent", "x")).unwrap_err();
        assert_eq!(e.kind, K::Network, "no response → retryable timeout");
        assert!(start.elapsed() >= Duration::from_millis(900), "retried 3 times");
        assert!(y.send(&Outbound::text("direct:ok", "x")).is_ok());
        assert_eq!(y.inner.resource_url("GONE").unwrap_err().kind, K::NotFound);
        assert_eq!(y.inner.resource_url("SLOW").unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(3)) });
        assert_eq!(y.inner.resource_url("OK").unwrap(), "https://real/x");
        let before = api.requests().iter().filter(|r| r.path == TOKEN_PATH).count();
        assert_eq!(y.inner.resource_url("AUTH").unwrap(), "https://real/x", "401 → re-sign → retry");
        assert_eq!(api.requests().iter().filter(|r| r.path == TOKEN_PATH).count(), before + 1);
        assert!(y.fetch_media(&Media::default()).is_err());
        y.stop();
    }

    #[test]
    fn reconnects_after_drop_and_missed_pongs_with_fresh_token() {
        let api = api_server();
        let pings = Arc::new(Mutex::new(Vec::new()));
        let p2 = pings.clone();
        let url = ws_server(move |i, mut ws| {
            auth(&mut ws);
            match i {
                // Answer one ping, then drop the TCP connection without a close frame.
                0 => {
                    let (h, _) = std::iter::from_fn(|| next(&mut ws, Duration::from_secs(3))).find(|(h, _)| h.cmd == "ping").unwrap();
                    p2.lock().unwrap().push(i);
                    respond(&mut ws, &h, &[]);
                    std::thread::sleep(Duration::from_millis(100));
                    let _ = ws.get_ref().shutdown(std::net::Shutdown::Both);
                }
                // Never answer pings → the client gives up after two misses.
                1 => {
                    let until = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < until {
                        match next(&mut ws, Duration::from_millis(100)) {
                            Some((h, _)) if h.cmd == "ping" => p2.lock().unwrap().push(i),
                            _ if ws.is_closed() => return,
                            _ => {}
                        }
                    }
                }
                _ => {
                    push(&mut ws, "p", &text_elem_push("amy", "", "after", vec![Elem::text("back")]), false);
                    let log: Log = Arc::new(Mutex::new(Vec::new()));
                    serve(&mut ws, &log, Instant::now() + Duration::from_secs(10));
                }
            }
        });
        let mut t = fast();
        t.heartbeat = Duration::from_millis(100);
        t.pong_timeout = Duration::from_millis(150);
        t.debounce = Duration::ZERO;
        let y = yb(&api.url, &url, t);
        let got = poll_n(&y, 1);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].message_id, "after");
        assert_eq!(api.requests().iter().filter(|r| r.path == TOKEN_PATH).count(), 3, "token force-refreshed on each reconnect");
        let p = pings.lock().unwrap().clone();
        assert!(p.contains(&0) && p.iter().filter(|&&c| c == 1).count() >= 2, "{p:?}");
        y.stop();
    }

    #[test]
    fn permanent_close_code_stops_with_auth_error() {
        let api = api_server();
        let conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = conns.clone();
        let url = ws_server(move |_, mut ws| {
            c2.fetch_add(1, Ordering::SeqCst);
            auth(&mut ws);
            ws.send(&Message::Close(Some((4012, "kicked".into())))).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });
        let y = yb(&api.url, &url, fast());
        let start = Instant::now();
        let e = loop {
            match y.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) => assert!(start.elapsed() < Duration::from_secs(5)),
            }
        };
        assert_eq!(e.kind, K::Auth);
        assert!(e.message.contains("4012"));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(conns.load(Ordering::SeqCst), 1, "no reconnect after a permanent close");
    }

    #[test]
    fn cancel_returns_promptly_from_a_blocked_poll() {
        let api = api_server();
        let url = ws_server(|_, mut ws| {
            auth(&mut ws);
            let log: Log = Arc::new(Mutex::new(Vec::new()));
            serve(&mut ws, &log, Instant::now() + Duration::from_secs(10));
        });
        let mut y = yb(&api.url, &url, fast());
        Arc::get_mut(&mut y.inner).unwrap().cfg.poll_timeout_secs = 30;
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(y.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
        y.stop();
    }

    #[test]
    fn build_validates_settings_and_secrets() {
        let d = temp_dir("yb");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:YB}}", "real-secret"));
        let ctx = crate::config::Ctx { name: "yb", state_dir: &d, secrets: &secrets };
        let ok = json!({"app_id": "AK", "app_secret": "{{secret:YB}}", "api_domain": "http://127.0.0.1:1", "ws_url": "ws://127.0.0.1:1/ws", "cos_base_url": "http://127.0.0.1:1", "debounce_ms": 0});
        let ch = build(&ctx, ok.as_object().unwrap()).unwrap();
        assert_eq!(ch.id(), "yb");
        assert!(ch.caps().typing && !ch.caps().edit && ch.caps().max_len == MAX_MESSAGE);
        let typo = json!({"app_id": "AK", "app_secret": "x", "app_secrt": "y"});
        assert!(build(&ctx, typo.as_object().unwrap()).err().unwrap().contains("app_secrt"));
        let missing = json!({"app_id": "AK", "app_secret": "{{secret:NOPE}}"});
        let e = build(&ctx, missing.as_object().unwrap()).err().unwrap();
        assert!(e.contains("not set") && !e.contains("real-secret"));
        assert!(build(&ctx, json!({"app_id": " ", "app_secret": "x"}).as_object().unwrap()).is_err());
    }
}
