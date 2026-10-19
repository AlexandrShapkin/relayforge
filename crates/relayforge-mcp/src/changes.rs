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

// A request must be approved within five minutes of preparation.
const APPROVAL_TTL_SECONDS: u64 = 300;
// Once approved, execution gets its own short window. An old approved
// record (without approval timestamp) retains its original earlier expiry.
const EXECUTION_TTL_SECONDS: u64 = 180;
const MAX_QUEUE: usize = 24;
const MAX_CONTENT: usize = 2048;
const ID_LEN: usize = 32;
const AUDIT_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
const DONE_RETENTION_SECONDS: u64 = 7 * 86400;

pub fn prepare_tool() -> Value {
    json!({"name":"relayforge_change_prepare",
          "description":"Prepare a tightly scoped change for manual approval within five minutes. After local approval, execution has its own 180-second window. Allowed: scratch create or inert probe restart on active hosts.",
        "inputSchema":{"type":"object","properties":{
            "host":{"type":"string","enum":["ru0","srv0"]},
            "action":{"type":"string","enum":["sandbox.create","probe.restart"]},
            "name":{"type":"string","maxLength":64,"description":"Only for sandbox.create: flat .txt/.md/.json filename"},
            "content":{"type":"string","maxLength":2048,"description":"Only for sandbox.create: up to 2048 UTF-8 bytes"}
        },"required":["host","action"],"additionalProperties":false}})
}

pub fn commit_tool() -> Value {
    json!({"name":"relayforge_change_commit",
         "description":"Execute a single-use approved change within 180 seconds of local terminal approval. No approval is possible through MCP; replay and expired grants are denied.",
        "inputSchema":{"type":"object","properties":{
            "approval_id":{"type":"string","minLength":32,"maxLength":32}
        },"required":["approval_id"],"additionalProperties":false}})
}

pub fn status_tool() -> Value {
    json!({"name":"relayforge_change_status",
         "description":"Check approval status and both separate approval/execution deadlines without revealing file contents.",
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

/// Effective execution deadline. Legacy approvals without the new fields
/// keep their original deadline: deploys must NEVER revive an old grant.
/// Partial/malformed new fields fail closed.
fn execution_deadline(record: &Value) -> Option<u64> {
    let prepared_expiry = record.get("expires")?.as_u64()?;
    match (
        record.get("approved_at_unix"),
        record.get("execution_expires_at_unix"),
    ) {
        (None, None) => Some(prepared_expiry),
        (Some(approved), Some(deadline)) => {
            let created = record.get("created")?.as_u64()?;
            let approved_at = approved.as_u64()?;
            let exec_expiry = deadline.as_u64()?;
            let expected = approved_at.checked_add(EXECUTION_TTL_SECONDS)?;
            if approved_at < created || approved_at >= prepared_expiry || exec_expiry != expected {
                None
            } else {
                Some(exec_expiry)
            }
        }
        _ => None,
    }
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
    if !["ru0", "srv0"].contains(&host) {
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
                let deadline = if stage == "prepared" {
                    record["expires"].as_u64()
                } else {
                    execution_deadline(&record)
                };
                if deadline.is_none_or(|expiry| expiry.saturating_add(keep_for) <= now) {
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
            "expires":created + APPROVAL_TTL_SECONDS,"proposal":proposal});
        self.audit(&id, operation, host, "prepared")
            .map_err(|_| "audit unavailable")?;
        self.save("prepared", &id, &record)
            .map_err(|_| "store unavailable")?;
        Ok(json!({"approval_id":id,"status":"awaiting_local_approval",
            "action":operation,"host":host,
            "expires_at_unix":created+APPROVAL_TTL_SECONDS,
            "approval_expires_at_unix":created+APPROVAL_TTL_SECONDS,
            "execution_window_seconds":EXECUTION_TTL_SECONDS,
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
        match action {
            "probe.restart" => {
                println!("Exact user service: relayforge-probe.service (restart on ru0)")
            }
            _ => {}
        }
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
        let confirmed_at = time_now().map_err(|_| "clock unavailable")?;
        let execution_expires = self.approve_confirmed(id, &record, confirmed_at)?;
        Ok(format!(
            "Approved single use for {host} / {action}; execute within {EXECUTION_TTL_SECONDS} seconds (expires at {execution_expires})"
        ))
    }

    /// This function is private and reachable in production only after the
    /// terminal displays the exact proposal and checks the typed phrase.
    /// Tests can provide explicit timestamps without sleeping.
    fn approve_confirmed(&self, id: &str, original: &Value, now: u64) -> Result<u64, String> {
        let prepared_expiry = original["expires"].as_u64().ok_or("invalid record")?;
        if now < original["created"].as_u64().ok_or("invalid record")? || now >= prepared_expiry {
            return Err("request expired".into());
        }
        if original.get("approved_at_unix").is_some()
            || original.get("execution_expires_at_unix").is_some()
        {
            return Err("prepared record already contains approval fields".into());
        }
        if self.load("prepared", id).map_err(|_| "request not found")? != *original {
            return Err("request modified since review".into());
        }
        let proposal = &original["proposal"];
        if parse_action(proposal)? != *proposal || original["id"].as_str() != Some(id) {
            return Err("request payload invalid".into());
        }
        let expiry = now
            .checked_add(EXECUTION_TTL_SECONDS)
            .ok_or("invalid clock")?;
        let mut approved = original.clone();
        approved["approved_at_unix"] = json!(now);
        approved["execution_expires_at_unix"] = json!(expiry);
        let action = proposal["action"].as_str().ok_or("invalid action")?;
        let host = proposal["host"].as_str().ok_or("invalid host")?;

        // Audit before granting execution rights: if auditing is broken,
        // nothing is approved. create_new prevents two approvers overwriting
        // one grant; its file is completely synced before the draft is deleted.
        self.audit(id, action, host, "operator_approved")
            .map_err(|_| "audit unavailable")?;
        self.save("approved", id, &approved)
            .map_err(|_| "approval already processed or store unavailable")?;
        fs::remove_file(self.file("prepared", id))
            .map_err(|_| "approved, but failed to clean pending record")?;
        Ok(expiry)
    }

    fn commit_with<F>(&self, id: &str, execute: F) -> Result<Value, String>
    where
        F: FnMut(&Value) -> Result<String, String>,
    {
        let now = time_now().map_err(|_| "clock unavailable")?;
        self.commit_with_at(id, now, execute)
    }

    fn commit_with_at<F>(&self, id: &str, now: u64, mut execute: F) -> Result<Value, String>
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
        if execution_deadline(&record).is_none_or(|expires| now >= expires) {
            return Err("execution approval expired or invalid".into());
        }
        if record["approved_at_unix"]
            .as_u64()
            .is_some_and(|approved| now < approved)
        {
            return Err("approval timestamp is in the future".into());
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
            "approved_at_unix":record.get("approved_at_unix"),
            "execution_expires_at_unix":record.get("execution_expires_at_unix"),
            "proposal":{"host":host,"action":action},"result":result});
        let mut saved = saved;
        if record.get("approved_at_unix").is_none() {
            saved.as_object_mut().unwrap().remove("approved_at_unix");
            saved
                .as_object_mut()
                .unwrap()
                .remove("execution_expires_at_unix");
        }
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
                let deadline = if stage == "prepared" {
                    record["expires"].as_u64()
                } else {
                    execution_deadline(&record)
                };
                let now = time_now().map_err(|_| "clock unavailable")?;
                let status = if (stage == "prepared" || stage == "approved")
                    && deadline.is_none_or(|expiry| now >= expiry)
                {
                    "expired"
                } else {
                    label
                };
                return Ok(json!({"approval_id":id,"status":status,
                    "expires_at_unix":deadline,
                    "approval_expires_at_unix":record["expires"],
                    "execution_expires_at_unix":if stage=="prepared" {
                        Value::Null
                    } else {
                        record.get("execution_expires_at_unix").cloned().unwrap_or(Value::Null)
                    },
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
            json!({"host":"ru0","action":"monitor.run"}),
            json!({"host":"srv0","action":"monitor.run"}),
            json!({"host":"ru1","action":"monitor.run","unit":"remote-desktop.service"}),
            json!({"host":"srv0","action":"service.restart","unit":"sshd.service"}),
            json!({"host":"ru0","action":"probe.restart","unit":"ssh.service"}),
            json!({"host":"ru0","action":"sandbox.create","name":"x.txt","content":"x","actor":"admin"}),
        ] {
            assert!(parse_action(&bad).is_err());
        }
    }
    #[test]
    fn retired_host_and_monitor_actions_are_always_denied() {
        assert!(parse_action(&json!({"host":"ru1","action":"monitor.run"})).is_err());
        assert!(parse_action(&json!({"host":"ru1","action":"sandbox.create",
            "name":"x.txt","content":"x"})).is_err());
        assert!(parse_action(&json!({"host":"ru0","action":"monitor.run"})).is_err());
        assert!(parse_action(&json!({"host":"srv0","action":"monitor.run"})).is_err());
        let s = store();
        assert!(s.prepare(&json!({"host":"ru1","action":"monitor.run"})).is_err());
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
            .prepare(&json!({"host":"ru0","action":"sandbox.create",
            "name":"draft.md","content":secret}))
            .unwrap();
        let audit = s.recent_audit().unwrap();
        let output = audit.to_string();
        assert!(output.contains("prepared"));
        assert!(output.contains("ru0"));
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
    fn late_confirmation_gets_fresh_execution_window() {
        let s = store();
        let prepared = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = prepared["approval_id"].as_str().unwrap();
        let original = s.load("prepared", id).unwrap();
        let original_expiry = original["expires"].as_u64().unwrap();
        let confirmed_at = original_expiry - 1;
        let execution_expiry = s.approve_confirmed(id, &original, confirmed_at).unwrap();
        assert_eq!(execution_expiry, confirmed_at + EXECUTION_TTL_SECONDS);
        assert!(execution_expiry > original_expiry);
        let new_record = s.load("approved", id).unwrap();
        assert_eq!(execution_deadline(&new_record), Some(execution_expiry));
        assert!(!s.file("prepared", id).exists());
        assert_eq!(
            s.status(id).unwrap()["execution_expires_at_unix"],
            execution_expiry
        );
        let mut runs = 0;
        let result = s
            .commit_with_at(id, original_expiry + 90, |_| {
                runs += 1;
                Ok("mock monitor success".into())
            })
            .unwrap();
        assert_eq!(result["status"], "succeeded");
        assert_eq!(runs, 1);
        assert_eq!(s.status(id).unwrap()["status"], "finished");
        assert_eq!(s.status(id).unwrap()["expires_at_unix"], execution_expiry);
    }

    #[test]
    fn confirmation_must_happen_before_original_deadline() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let orig = s.load("prepared", id).unwrap();
        let prepared_expires = orig["expires"].as_u64().unwrap();
        assert!(s.approve_confirmed(id, &orig, prepared_expires).is_err());
        assert!(s
            .approve_confirmed(id, &orig, prepared_expires + 20)
            .is_err());
        assert!(s
            .approve_confirmed(id, &orig, orig["created"].as_u64().unwrap() - 1)
            .is_err());
        assert!(!s.file("approved", id).exists());
        assert_eq!(s.status(id).unwrap()["status"], "awaiting_local_approval");
    }

    #[test]
    fn execution_expiry_is_exclusive_and_approval_is_single_use() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let orig = s.load("prepared", id).unwrap();
        let approved_at = orig["created"].as_u64().unwrap() + 1;
        let expires = s.approve_confirmed(id, &orig, approved_at).unwrap();
        let mut attempts = 0;
        assert!(s
            .commit_with_at(id, expires, |_| {
                attempts += 1;
                Ok("unexpected".into())
            })
            .is_err());
        assert!(s
            .commit_with_at(id, expires + 1, |_| {
                attempts += 1;
                Ok("unexpected".into())
            })
            .is_err());
        assert!(s
            .commit_with_at(id, approved_at - 1, |_| {
                attempts += 1;
                Ok("unexpected".into())
            })
            .is_err());
        assert_eq!(attempts, 0);
        assert!(s.file("approved", id).exists());
        assert!(s
            .commit_with_at(id, expires - 1, |_| {
                attempts += 1;
                Ok("mock".into())
            })
            .is_ok());
        assert_eq!(attempts, 1);
        assert!(s
            .commit_with_at(id, expires - 1, |_| {
                attempts += 1;
                Ok("replay".into())
            })
            .is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn legacy_approved_grants_are_not_extended_on_upgrade() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let original = s.load("prepared", id).unwrap();
        let original_expiry = original["expires"].as_u64().unwrap();
        s.move_stage("prepared", "approved", id).unwrap();
        assert_eq!(
            execution_deadline(&s.load("approved", id).unwrap()),
            Some(original_expiry)
        );
        let mut calls = 0;
        assert!(s
            .commit_with_at(id, original_expiry, |_| {
                calls += 1;
                Ok("unexpected".into())
            })
            .is_err());
        assert_eq!(calls, 0);
        assert!(s
            .commit_with_at(id, original_expiry - 1, |_| {
                calls += 1;
                Ok("legacy mock".into())
            })
            .is_ok());
        assert_eq!(calls, 1);
        assert_eq!(
            s.status(id).unwrap()["execution_expires_at_unix"],
            Value::Null
        );
        assert_eq!(s.status(id).unwrap()["expires_at_unix"], original_expiry);
    }

    #[test]
    fn tampered_execution_window_fails_closed() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let original = s.load("prepared", id).unwrap();
        let at = original["created"].as_u64().unwrap() + 1;
        let expires = s.approve_confirmed(id, &original, at).unwrap();
        let trusted = s.load("approved", id).unwrap();
        for mut bad in [
            {
                let mut v = trusted.clone();
                v["execution_expires_at_unix"] = json!(expires + 100);
                v
            },
            {
                let mut v = trusted.clone();
                v["execution_expires_at_unix"] = Value::Null;
                v
            },
            {
                let mut v = trusted.clone();
                v["approved_at_unix"] = Value::Null;
                v
            },
            {
                let mut v = trusted.clone();
                v["approved_at_unix"] = json!(original["expires"].as_u64().unwrap());
                v
            },
            {
                let mut v = trusted.clone();
                v["approved_at_unix"] = json!(0);
                v
            },
        ] {
            assert_eq!(execution_deadline(&bad), None, "{bad}");
            // Do not permit partial approval metadata to become a legacy
            // grant accidentally, which could revive expired permissions.
            bad["execution_expires_at_unix"] = json!("invalid");
            assert_eq!(execution_deadline(&bad), None);
        }
        let mut partial = trusted.clone();
        partial.as_object_mut().unwrap().remove("approved_at_unix");
        assert_eq!(execution_deadline(&partial), None);
    }

    #[test]
    fn approved_window_survives_cleanup_until_its_own_expiry() {
        let s = store();
        let data = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = data["approval_id"].as_str().unwrap();
        let original = s.load("prepared", id).unwrap();
        let prepared_expires = original["expires"].as_u64().unwrap();
        let exec_expires = s
            .approve_confirmed(id, &original, prepared_expires - 1)
            .unwrap();
        s.prune_expired(prepared_expires + 1).unwrap();
        assert!(s.file("approved", id).exists());
        s.prune_expired(exec_expires).unwrap();
        assert!(!s.file("approved", id).exists());
    }

    #[test]
    fn audit_failure_prevents_confirmed_grant_creation() {
        let s = store();
        let prepared = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = prepared["approval_id"].as_str().unwrap();
        let original = s.load("prepared", id).unwrap();
        let path = s.dir.join("audit.jsonl");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let now = original["created"].as_u64().unwrap() + 2;
        assert!(s.approve_confirmed(id, &original, now).is_err());
        assert!(!s.file("approved", id).exists());
        assert!(s.file("prepared", id).exists());
    }

    #[test]
    fn competing_commits_execute_a_grant_at_most_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let s = store();
        let prepared = s
            .prepare(&json!({"host":"ru0","action":"probe.restart"}))
            .unwrap();
        let id = prepared["approval_id"].as_str().unwrap();
        let record = s.load("prepared", id).unwrap();
        let approved_at = record["created"].as_u64().unwrap() + 1;
        s.approve_confirmed(id, &record, approved_at).unwrap();
        let runs = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..8)
                .map(|_| {
                    let store = s.clone();
                    let runs = &runs;
                    scope.spawn(move || {
                        store.commit_with_at(id, approved_at + 1, |_| {
                            runs.fetch_add(1, Ordering::SeqCst);
                            Ok("mock".into())
                        })
                    })
                })
                .collect();
            let succeeded = jobs
                .into_iter()
                .map(|j| usize::from(j.join().unwrap().is_ok()))
                .sum::<usize>();
            assert_eq!(succeeded, 1);
        });
        assert_eq!(runs.load(Ordering::SeqCst), 1);
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
