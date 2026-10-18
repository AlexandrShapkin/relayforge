//! Short-lived, single-use operator approvals for strictly allowlisted changes.
//! A remote MCP caller cannot approve: approval requires an interactive local
//! terminal. This is NOT per-ChatGPT-actor authentication.
use serde_json::{json, Value};
use std::{
    env,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const TTL_SECONDS: u64 = 300;
const MAX_QUEUE: usize = 24;
const MAX_CONTENT: usize = 2048;
const ID_LEN: usize = 32;
const AUDIT_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
const DONE_RETENTION_SECONDS: u64 = 7 * 86400;

pub fn prepare_tool() -> Value {
    json!({"name":"relayforge_change_prepare",
        "description":"Prepare a tightly scoped change requiring separate interactive ThinkPad terminal approval. Does not perform it. Only scratch file creation on ru0/ru1/srv0 or inert probe restart on ru0.",
        "inputSchema":{"type":"object","properties":{
            "host":{"type":"string","enum":["ru0","ru1","srv0"]},
            "action":{"type":"string","enum":["sandbox.create","probe.restart"]},
            "name":{"type":"string","maxLength":64,"description":"Only for sandbox.create: flat .txt/.md/.json filename"},
            "content":{"type":"string","maxLength":2048,"description":"Only for sandbox.create: up to 2048 UTF-8 bytes"}
        },"required":["host","action"],"additionalProperties":false}})
}

pub fn commit_tool() -> Value {
    json!({"name":"relayforge_change_commit",
        "description":"Execute an exact pre-approved, unexpired, single-use change. Approval is issued from a local interactive ThinkPad terminal, not by the RelayForge MCP tools.",
        "inputSchema":{"type":"object","properties":{
            "approval_id":{"type":"string","minLength":32,"maxLength":32}
        },"required":["approval_id"],"additionalProperties":false}})
}

pub fn status_tool() -> Value {
    json!({"name":"relayforge_change_status",
        "description":"Show the status of an approval by its identifier, without revealing file contents.",
        "inputSchema":{"type":"object","properties":{
            "approval_id":{"type":"string","minLength":32,"maxLength":32}
        },"required":["approval_id"],"additionalProperties":false}})
}

pub fn audit_tool() -> Value {
    json!({"name":"relayforge_change_audit",
        "description":"Read up to 20 recent local change-approval audit events. Does not expose request payloads or secrets.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
}

fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn time_now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(io::Error::other)
}

fn random_id() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut result = String::with_capacity(ID_LEN);
    for byte in bytes {
        write!(result, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(result)
}

fn valid_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
        && [".txt", ".md", ".json"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

fn parse_action(args: &Value) -> Result<Value, String> {
    let obj = args.as_object().ok_or("expected object")?;
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .ok_or("missing host")?;
    if !["ru0", "ru1", "srv0"].contains(&host) {
        return Err("host denied".into());
    }
    match obj.get("action").and_then(Value::as_str) {
        Some("sandbox.create") if obj.len() == 4 => {
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or("missing filename")?;
            let content = obj
                .get("content")
                .and_then(Value::as_str)
                .ok_or("missing content")?;
            if !valid_file_name(name) || content.len() > MAX_CONTENT {
                return Err("file parameters denied".into());
            }
            Ok(json!({"host":host,"action":"sandbox.create","name":name,"content":content}))
        }
        Some("probe.restart") if host == "ru0" && obj.len() == 2 => {
            Ok(json!({"host":"ru0","action":"probe.restart"}))
        }
        _ => Err("operation denied".into()),
    }
}

fn valid_file(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "insecure approval file",
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct Store {
    dir: PathBuf,
}

impl Store {
    fn current() -> io::Result<Self> {
        let home = PathBuf::from(
            env::var_os("HOME").ok_or(io::Error::new(io::ErrorKind::NotFound, "HOME missing"))?,
        );
        let root = home.join(".local/state/relayforge");
        Self::at(root)
    }

    fn at(dir: PathBuf) -> io::Result<Self> {
        let meta = fs::symlink_metadata(&dir)?;
        let home_uid = fs::metadata(env::var_os("HOME").unwrap_or_default())?.uid();
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o077 != 0
            || meta.uid() != home_uid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approval store not private",
            ));
        }
        for part in ["prepared", "approved", "claimed", "done"] {
            let child = fs::symlink_metadata(dir.join(part))?;
            if !child.is_dir()
                || child.file_type().is_symlink()
                || child.permissions().mode() & 0o077 != 0
                || child.uid() != home_uid
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "approval stage not private",
                ));
            }
        }
        Ok(Self { dir })
    }

    fn file(&self, stage: &str, id: &str) -> PathBuf {
        self.dir.join(stage).join(format!("{id}.json"))
    }

    fn audit(&self, id: &str, operation: &str, host: &str, event: &str) -> io::Result<()> {
        let path = self.dir.join("audit.jsonl");
        match fs::symlink_metadata(&path) {
            Ok(_) => valid_file(&path)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.len() >= AUDIT_LIMIT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "audit capacity reached",
                ));
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        let record = json!({
            "at": time_now()?, "id":id, "host":host,
            "operation":operation,"event":event
        });
        writeln!(file, "{record}")?;
        file.sync_all()
    }

    fn save(&self, stage: &str, id: &str, record: &Value) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.file(stage, id))?;
        file.write_all(record.to_string().as_bytes())?;
        file.sync_all()
    }

    fn load(&self, stage: &str, id: &str) -> io::Result<Value> {
        let path = self.file(stage, id);
        valid_file(&path)?;
        let file = File::open(path)?;
        let mut buf = Vec::new();
        file.take(4096).read_to_end(&mut buf)?;
        if buf.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid approval record",
            ));
        }
        serde_json::from_slice(&buf).map_err(io::Error::other)
    }

    fn move_stage(&self, from: &str, to: &str, id: &str) -> io::Result<()> {
        // hard_link is atomic and refuses an existing destination, unlike
        // rename() which can overwrite a raced-in destination. After linking,
        // a second contender always fails closed. A crash between link and
        // unlink leaves a locked destination, not a reusable approval.
        fs::hard_link(self.file(from, id), self.file(to, id))?;
        fs::remove_file(self.file(from, id))
    }

    fn prune_expired(&self, now: u64) -> io::Result<()> {
        for (stage, keep_for) in [
            ("prepared", 0),
            ("approved", 0),
            ("done", DONE_RETENTION_SECONDS),
        ] {
            for entry in fs::read_dir(self.dir.join(stage))?.take(4096) {
                let entry = entry?;
                let Some(id) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_suffix(".json"))
                    .map(ToOwned::to_owned)
                else {
                    continue;
                };
                if !valid_id(&id) {
                    continue;
                }
                let Ok(record) = self.load(stage, &id) else {
                    continue;
                };
                if record["expires"]
                    .as_u64()
                    .is_some_and(|expiry| expiry.saturating_add(keep_for) <= now)
                {
                    fs::remove_file(self.file(stage, &id))?;
                }
            }
        }
        Ok(())
    }

    fn recent_audit(&self) -> io::Result<Value> {
        let path = self.dir.join("audit.jsonl");
        match fs::symlink_metadata(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(json!({"events":[],"limit":20}))
            }
            Err(err) => return Err(err),
            Ok(_) => valid_file(&path)?,
        }
        const TAIL: u64 = 32 * 1024;
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        if length > TAIL {
            file.seek(SeekFrom::Start(length - TAIL))?;
        }
        let mut content = String::new();
        file.take(TAIL).read_to_string(&mut content)?;
        let valid_part = if length > TAIL {
            content.split_once('\n').map_or("", |(_, tail)| tail)
        } else {
            &content
        };
        let events: Vec<Value> = valid_part
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["id"].is_string() && entry["event"].is_string())
            .collect();
        Ok(
            json!({"events":events.into_iter().rev().take(20).collect::<Vec<_>>(),
            "limit":20}),
        )
    }

    fn pending_count(&self) -> io::Result<usize> {
        Ok(fs::read_dir(self.dir.join("prepared"))?
            .take(MAX_QUEUE + 1)
            .count()
            + fs::read_dir(self.dir.join("approved"))?
                .take(MAX_QUEUE + 1)
                .count())
    }

    fn prepare(&self, args: &Value) -> Result<Value, String> {
        let proposal = parse_action(args)?;
        let now = time_now().map_err(|_| "clock unavailable")?;
        self.prune_expired(now)
            .map_err(|_| "approval cleanup unavailable")?;
        if self.pending_count().map_err(|_| "store unavailable")? >= MAX_QUEUE {
            return Err("approval queue full".into());
        }
        let id = random_id().map_err(|_| "entropy unavailable")?;
        let created = now;
        let operation = proposal["action"].as_str().ok_or("invalid action")?;
        let host = proposal["host"].as_str().ok_or("invalid host")?;
        let record = json!({"id":id,"created":created,
            "expires":created + TTL_SECONDS,"proposal":proposal});
        self.audit(&id, operation, host, "prepared")
            .map_err(|_| "audit unavailable")?;
        self.save("prepared", &id, &record)
            .map_err(|_| "store unavailable")?;
        Ok(json!({"approval_id":id,"status":"awaiting_local_approval",
            "action":operation,"host":host,"expires_at_unix":created+TTL_SECONDS,
            "approval_command":format!("~/Projects/relayforge/target/release/relayforge-mcp --approve-change {id}")}))
    }

    fn approve(&self, id: &str, interactive: bool) -> Result<String, String> {
        if !valid_id(id) {
            return Err("invalid approval ID".into());
        }
        let record = self.load("prepared", id).map_err(|_| "request not found")?;
        let now = time_now().map_err(|_| "clock unavailable")?;
        if record["expires"].as_u64().is_none_or(|ts| ts <= now) {
            return Err("request expired".into());
        }
        let prop = &record["proposal"];
        let action = prop["action"].as_str().ok_or("invalid record")?;
        let host = prop["host"].as_str().ok_or("invalid record")?;
        println!("RelayForge approval ID: {id}");
        println!("Target host: {host} | Exact action: {action}");
        if action == "sandbox.create" {
            println!(
                "Scratch filename: {}",
                prop["name"].as_str().unwrap_or("<invalid>")
            );
            let contents = prop["content"].as_str().ok_or("invalid record")?;
            // JSON escaping prevents terminal control sequences embedded in a
            // remote-supplied file payload from manipulating the operator UI.
            println!(
                "Contents (JSON escaped): {}",
                serde_json::to_string(contents).map_err(|_| "invalid content")?
            );
        }
        println!(
            "Expires in: {} seconds",
            record["expires"].as_u64().unwrap_or(0) - now
        );
        if !interactive {
            return Err("interactive local approval required".into());
        }
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err("an interactive terminal is required".into());
        }
        print!("Type APPROVE {id} to authorize this exact one-time operation: ");
        io::stdout().flush().map_err(|_| "terminal unavailable")?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|_| "terminal unavailable")?;
        if input.trim_end() != format!("APPROVE {id}") {
            return Err("approval rejected".into());
        }
        if record["expires"]
            .as_u64()
            .is_none_or(|ts| ts <= time_now().unwrap_or(u64::MAX))
        {
            return Err("request expired".into());
        }
        self.audit(id, action, host, "operator_approved")
            .map_err(|_| "audit unavailable")?;
        self.move_stage("prepared", "approved", id)
            .map_err(|_| "approval already processed")?;
        Ok(format!(
            "Approved single use for {host} / {action}; expires at {}",
            record["expires"]
        ))
    }

    fn commit_with<F>(&self, id: &str, mut execute: F) -> Result<Value, String>
    where
        F: FnMut(&Value) -> Result<String, String>,
    {
        if !valid_id(id) {
            return Err("invalid approval ID".into());
        }
        let record = self
            .load("approved", id)
            .map_err(|_| "not approved or already used")?;
        let prop = &record["proposal"];
        let action = prop["action"].as_str().ok_or("invalid record")?;
        let host = prop["host"].as_str().ok_or("invalid record")?;
        if record["expires"]
            .as_u64()
            .is_none_or(|ts| ts <= time_now().unwrap_or(u64::MAX))
        {
            return Err("approval expired".into());
        }
        // Revalidate the approved payload before using the network.
        if parse_action(prop)? != *prop {
            return Err("approval payload invalid".into());
        }
        self.move_stage("approved", "claimed", id)
            .map_err(|_| "approval already used")?;
        // Fail closed if durable audit cannot record the attempt.
        self.audit(id, action, host, "execution_started")
            .map_err(|_| "audit unavailable")?;
        let outcome = execute(prop);
        let (status, message, event) = match outcome {
            Ok(message) => ("succeeded", message, "execution_succeeded"),
            Err(message) => ("failed", message, "execution_failed"),
        };
        let result = json!({"approval_id":id,"status":status,
            "host":host,"action":action,"result":message});
        self.audit(id, action, host, event)
            .map_err(|_| "audit unavailable")?;
        let saved = json!({"id":id,"created":record["created"],"expires":record["expires"],
            "proposal":{"host":host,"action":action},"result":result});
        self.save("done", id, &saved)
            .map_err(|_| "audit unavailable")?;
        fs::remove_file(self.file("claimed", id)).map_err(|_| "audit unavailable")?;
        Ok(result)
    }

    fn status(&self, id: &str) -> Result<Value, String> {
        if !valid_id(id) {
            return Err("invalid approval ID".into());
        }
        for (stage, label) in [
            ("done", "finished"),
            ("claimed", "in_progress"),
            ("approved", "approved"),
            ("prepared", "awaiting_local_approval"),
        ] {
            if let Ok(record) = self.load(stage, id) {
                return Ok(json!({"approval_id":id,"status":label,
                    "expires_at_unix":record["expires"],
                    "result":if stage=="done" {record["result"].clone()} else {Value::Null}}));
            }
        }
        Err("request not found".into())
    }
}

pub fn prepare(args: &Value) -> Result<String, String> {
    Store::current()
        .map_err(|_| "approval store unavailable".to_string())?
        .prepare(args)
        .map(|value| value.to_string())
}
pub fn commit(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("invalid arguments")?;
    if obj.len() != 1 {
        return Err("invalid arguments".into());
    }
    let id = obj
        .get("approval_id")
        .and_then(Value::as_str)
        .ok_or("missing approval_id")?;
    Store::current()
        .map_err(|_| "approval store unavailable".to_string())?
        .commit_with(id, |proposal| match proposal["action"].as_str() {
            Some("sandbox.create") => crate::agent::file_query(&json!({
                "host":proposal["host"], "operation":"file.create",
                "name":proposal["name"],"content":proposal["content"]
            })),
            Some("probe.restart") => crate::agent::restart_probe(&json!({"host":proposal["host"]})),
            _ => Err("operation denied".into()),
        })
        .map(|value| value.to_string())
}
pub fn status(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("invalid arguments")?;
    if obj.len() != 1 {
        return Err("invalid arguments".into());
    }
    let id = obj
        .get("approval_id")
        .and_then(Value::as_str)
        .ok_or("missing approval_id")?;
    Store::current()
        .map_err(|_| "approval store unavailable".to_string())?
        .status(id)
        .map(|value| value.to_string())
}

pub fn audit_recent(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|obj| !obj.is_empty()) {
        return Err("unexpected arguments".into());
    }
    Store::current()
        .map_err(|_| "approval store unavailable".to_string())?
        .recent_audit()
        .map(|v| v.to_string())
        .map_err(|_| "audit unavailable".into())
}

pub fn approve_local(id: &str) -> io::Result<()> {
    let store = Store::current()?;
    match store.approve(id, true) {
        Ok(message) => {
            println!("{message}");
            Ok(())
        }
        Err(message) => Err(io::Error::other(message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> Store {
        let root = env::temp_dir().join(format!("rf-approvals-test-{}", random_id().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["prepared", "approved", "claimed", "done"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        Store::at(root).unwrap()
    }
    #[test]
    fn rejects_untrusted_mutations() {
        for bad in [
            json!({"host":"ru0","action":"sandbox.create","name":"../evil.md","content":"x"}),
            json!({"host":"ru0","action":"sandbox.create","name":"ok.sh","content":"x"}),
            json!({"host":"ru1","action":"probe.restart"}),
            json!({"host":"srv0","action":"service.restart","unit":"sshd.service"}),
            json!({"host":"ru0","action":"probe.restart","unit":"ssh.service"}),
            json!({"host":"ru0","action":"sandbox.create","name":"x.txt","content":"x","actor":"admin"}),
        ] {
            assert!(parse_action(&bad).is_err());
        }
    }
    #[test]
    fn no_execution_without_operator_approval() {
        let s = store();
        let prepared = s
            .prepare(&json!({"host":"ru0","action":"sandbox.create",
            "name":"draft.txt","content":"hi"}))
            .unwrap();
        let id = prepared["approval_id"].as_str().unwrap();
        let mut calls = 0;
        assert!(s
            .commit_with(id, |_| {
                calls += 1;
                Ok("done".into())
            })
            .is_err());
        assert_eq!(calls, 0);
        assert!(s.approve(id, false).is_err());
        assert_eq!(s.status(id).unwrap()["status"], "awaiting_local_approval");
    }
    #[test]
    fn approved_operation_is_single_use() {
        let s = store();
        let prepared = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = prepared["approval_id"].as_str().unwrap();
        // Test fixture simulates a human-approved staged grant. Production
        // approval is ONLY through approve_local + an interactive terminal.
        s.move_stage("prepared", "approved", id).unwrap();
        let mut count = 0;
        let result = s
            .commit_with(id, |_| {
                count += 1;
                Ok("mock".into())
            })
            .unwrap();
        assert_eq!(result["status"], "succeeded");
        assert!(s
            .commit_with(id, |_| {
                count += 1;
                Ok("bad".into())
            })
            .is_err());
        assert_eq!(count, 1);
        assert_eq!(s.status(id).unwrap()["status"], "finished");
        let audit = fs::read_to_string(s.dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("execution_succeeded"));
        assert!(!audit.contains("mock"));
    }
    #[test]
    fn expiry_pruning_releases_queue_slots() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"sandbox.create",
            "name":"old.json","content":"{}"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let mut record = s.load("prepared", id).unwrap();
        record["expires"] = json!(1);
        fs::remove_file(s.file("prepared", id)).unwrap();
        s.save("prepared", id, &record).unwrap();
        assert!(s.file("prepared", id).exists());
        let fresh = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        assert!(fresh["approval_id"].is_string());
        assert!(!s.file("prepared", id).exists());
    }
    #[test]
    fn audit_exposes_events_but_not_request_content() {
        let s = store();
        let secret = "sensitive-test-content-only";
        let _ = s
            .prepare(&json!({"host":"ru1","action":"sandbox.create",
            "name":"draft.md","content":secret}))
            .unwrap();
        let audit = s.recent_audit().unwrap();
        let output = audit.to_string();
        assert!(output.contains("prepared"));
        assert!(output.contains("ru1"));
        assert!(!output.contains(secret));
        assert_eq!(audit["events"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_approval_directory_permissions_must_be_private() {
        let s = store();
        fs::set_permissions(&s.dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::at(s.dir).is_err());
    }

    #[test]
    fn expired_and_tampered_grants_fail_closed() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let mut record = s.load("prepared", id).unwrap();
        record["expires"] = json!(1);
        fs::remove_file(s.file("prepared", id)).unwrap();
        s.save("approved", id, &record).unwrap();
        assert!(s.commit_with(id, |_| Ok("bad".into())).is_err());
        assert!(s.approve(id, false).is_err());
        assert!(!valid_id("anything"));
    }
}
