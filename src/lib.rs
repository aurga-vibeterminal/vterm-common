use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

pub mod diagnostics;
pub mod latency;
pub mod private_ca;
pub mod proxy;
pub mod screen_perf_log;
pub mod tls;
#[cfg(target_os = "windows")]
pub mod windows_shutdown;

pub use screen_perf_log::screen_perf_log_enabled;

// Terminal grid model types live in `vterm-emulator` so that crate is
// self-contained (embeddable in mobile apps without the rest of the
// workspace). Re-exported here for backwards compatibility.
pub use vterm_emulator::{bitflags, Cell, CellAttributes, Color, TerminalSize};

/// Unique identifier for terminal sessions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use a shorter format for easier sharing (first 8 chars of UUID)
        write!(f, "{}", self.0.to_string().split_at(8).0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SessionApp(pub String);

impl SessionApp {
    pub fn none() -> Self {
        Self(String::new())
    }

    pub fn is_none(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_some(&self) -> bool {
        !self.0.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionAppStatus {
    #[default]
    None,
    Idle,
    Busy,
    Selection,
    ConfirmingNormal,
    ConfirmingSpecial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionTerminalOs {
    #[default]
    Windows,
    Linux,
    Macos,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentProfileInfo {
    pub id: String,
    pub name: String,
}

/// Tree-shaped projection of the environment configuration sent to terminal
/// clients so they can render a hierarchical picker. Groups are folders; Leaves
/// are environment-variable collections that can be applied to a session.
///
/// Tagged with `kind` ("group" / "leaf") on the wire. Leaves carry only id+name
/// (the variables themselves are never sent to the client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EnvironmentNodeInfo {
    Group {
        id: String,
        name: String,
        children: Vec<EnvironmentNodeInfo>,
    },
    Leaf {
        id: String,
        name: String,
    },
}

pub type TabId = SessionId;
pub type TabGroupId = u32;

pub const TAB_GROUP_UNGROUPED_ID: TabGroupId = 0;
pub const TAB_GROUP_ALL_ID: TabGroupId = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabGroup {
    pub server_id: Option<String>,
    pub id: TabGroupId,
    pub name: String,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tab_ids: Vec<TabId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalLayoutDirection {
    Horizontal,
    Vertical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TabSplitPlacement {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalLayout {
    Terminal {
        session_id: SessionId,
    },
    Split {
        direction: TerminalLayoutDirection,
        #[serde(default = "default_split_percent")]
        first_percent: f32,
        first: Box<TerminalLayout>,
        second: Box<TerminalLayout>,
    },
}

fn default_split_percent() -> f32 {
    50.0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TabInfo {
    pub server_id: Option<String>,
    pub tab_id: TabId,
    pub sessions: Vec<SessionInfo>,
    pub layout: TerminalLayout,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    #[serde(default)]
    pub tab_id: TabId,
    #[serde(default)]
    pub group_id: u32,
    #[serde(default)]
    pub tab_group_id: TabGroupId,
    pub title: String,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    #[serde(default, skip)]
    pub size: TerminalSize,
    pub viewer_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_working_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewing_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_type: Option<String>,
    /// Character encoding used by this terminal's byte stream. `None` means
    /// the default UTF-8 behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Whether this session is backed by a configured UART/serial port.
    #[serde(default)]
    pub is_uart: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_os: Option<SessionTerminalOs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_os: Option<SessionTerminalOs>,
    #[serde(default)]
    pub app: SessionApp,
    #[serde(default)]
    pub app_status: SessionAppStatus,
    /// One-line summary of what the agent is waiting for when `app_status` is a
    /// confirmation/selection state (e.g. "Confirm file edit for Foo.tsx").
    /// `None` when there is no pending attention. Snapshotted so a
    /// newly-connecting client can show the pending confirmation immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_status_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<EnvironmentProfileInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments_tree: Vec<EnvironmentNodeInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_files: Vec<String>,
    #[serde(default = "default_true")]
    pub notification_enabled: bool,
    #[serde(default)]
    pub auto_confirm_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitFileStatus {
    Modified,
    Added,
    Deleted,
    Untracked,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitChangedFile {
    pub file: String,
    pub status: GitFileStatus,
    #[serde(default)]
    pub staged: bool,
    /// True when this entry is a gitlink (mode 160000) in the current repo.
    #[serde(default)]
    pub is_submodule: bool,
    /// The submodule worktree contains tracked or untracked uncommitted changes.
    #[serde(default)]
    pub submodule_dirty: bool,
}

/// One entry of `git stash list`, newest first (index 0 = `stash@{0}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStashEntry {
    /// Stash index (`stash@{index}`).
    pub index: u32,
    /// Custom stash message, or the default `WIP on <branch>: ...` subject.
    pub message: String,
    /// Branch the stash was created on.
    pub branch: String,
    /// Relative creation time (e.g. "2 hours ago").
    pub date: String,
    /// Files touched by the stash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<GitChangedFile>,
}

/// One submodule of the active repository (whether or not its pointer is
/// modified in the working tree).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSubmoduleInfo {
    /// Path of the submodule relative to the active repository root.
    pub path: String,
    /// Current branch of the submodule worktree, when on a branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Short commit hash when HEAD is detached (or the submodule is not
    /// initialized, in which case this is the recorded gitlink hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_detached: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCommitInfo {
    pub hash: String,
    pub message: String,
    pub author: String,
    pub date: String,
    #[serde(default)]
    pub exact_time: String,
    #[serde(default)]
    pub parents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitBranchInfo {
    pub name: String,
    pub is_current: bool,
    pub is_remote: bool,
    /// Absolute path of the linked worktree this local branch is checked out
    /// in, when applicable. `None` for remote branches, tags, and local
    /// branches checked out in the main working tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_path: Option<String>,
}

/// One entry of an interactive-rebase todo list (a commit unique to the
/// branch being rebased, oldest first = apply order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRebaseTodoCommit {
    pub hash: String,
    pub message: String,
    pub author: String,
    pub date: String,
    /// Action for the apply step: "pick" | "squash" | "fixup" | "edit" | "drop".
    #[serde(default = "default_rebase_action")]
    pub action: String,
}

fn default_rebase_action() -> String {
    "pick".to_string()
}

/// Commit details for hover tips: hash, subject, author, relative date.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCommitMeta {
    pub hash: String,
    pub message: String,
    pub author: String,
    pub date: String,
}

/// Server-side state of an in-progress (or finished) rebase, returned
/// after apply / continue / skip.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRebaseState {
    /// True when the rebase finished (no conflict, nothing in progress).
    pub done: bool,
    /// 1-based index of the commit being applied when the rebase stopped.
    #[serde(default)]
    pub step: usize,
    /// Total number of commits to apply.
    #[serde(default)]
    pub total: usize,
    /// Hash + subject of the commit the rebase stopped at (on conflict).
    #[serde(default)]
    pub commit_hash: String,
    #[serde(default)]
    pub commit_message: String,
    /// Author + relative date of the stopped commit (for hover tips).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub commit_author: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub commit_date: String,
    /// Metadata of the base commit (HEAD while the rebase is stopped) —
    /// the "ours"/target side of conflict hunks, shown in hover tips.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_author: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_date: String,
    /// Unmerged (conflicted) paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflict_files: Vec<String>,
    /// True when the rebase paused without file conflicts (an empty
    /// commit, or an `edit` breakpoint). Continue would stall on the
    /// empty pick — the client should offer Skip instead.
    #[serde(default)]
    pub empty: bool,
}

/// Per-hunk analysis result from LLM code analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HunkAnalysis {
    pub old_start: u32,
    pub old_count: u32,
    pub new_start: u32,
    pub new_count: u32,
    pub analysis: String,
}

/// One unresolved conflict hunk handed to the AI rebase resolver. `idx` is
/// the hunk's index in the file's client-side diff3 chunk list; the three
/// sides are the hunk's line arrays (split without terminators).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRebaseAiHunk {
    pub idx: u32,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub ours: Vec<String>,
    #[serde(default)]
    pub theirs: Vec<String>,
}

/// All hunks the AI should resolve for one conflicted file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRebaseAiTarget {
    pub path: String,
    #[serde(default)]
    pub hunks: Vec<GitRebaseAiHunk>,
}

/// One streamed per-hunk event of an AI resolve run. `status` is "running"
/// (analysis started), "done" (resolution fields set), or "error" (`error`
/// set, hunk left unresolved).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitRebaseAiHunkEvent {
    pub path: String,
    pub idx: u32,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<Vec<String>>,
    /// "ours" | "theirs" | "union" | "custom".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileListItem {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dir: Option<bool>,
    #[serde(default)]
    pub git_modified: bool,
    #[serde(default)]
    pub git_ignored: bool,
}

impl FileListItem {
    pub fn file(name: String) -> Self {
        Self {
            name,
            is_dir: None,
            git_modified: false,
            git_ignored: false,
        }
    }

    pub fn directory(name: String) -> Self {
        Self {
            name,
            is_dir: Some(true),
            git_modified: false,
            git_ignored: false,
        }
    }
}

/// A file or folder whose name matched a `SearchPathNames` query. Paths are
/// absolute (rooted at the nailed folder the search was issued under); `is_dir`
/// distinguishes folders (which the client may expand) from files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathNameMatch {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSearchMatch {
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSearchResult {
    pub file: String,
    pub path: String,
    pub matches: Vec<FileSearchMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentProjectDirectory {
    pub path: String,
    pub accessed_at_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownAppInfo {
    pub executable: String,
    pub display_name: String,
    /// Where this app's MCP setup line must be typed. Terminal-command apps
    /// (the default — `executable mcp add …`) work in a plain shell;
    /// conversation-style apps have no `mcp add` CLI, so their setup line
    /// (e.g. Kimi's `/mcp-config` chat prompt) must be typed inside the
    /// running app. The client uses it to decide which apps to offer in the
    /// terminal's MCP context menu.
    #[serde(default)]
    pub mcp_command_target: McpCommandTarget,
}

/// Where an MCP setup command is meant to be typed (see
/// `KnownAppInfo::mcp_command_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpCommandTarget {
    /// A shell command typed into a plain terminal (`executable mcp add …`).
    #[default]
    Terminal,
    /// A chat prompt typed into the app's own conversation
    /// (e.g. Kimi Code's `/mcp-config …`).
    InApp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalCommandHistory {
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiConversationInfo {
    pub id: String,
    pub time: String,
    pub brief: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiConversationRole {
    User,
    Model,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiConversationMessageKind {
    Text,
    Thinking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiConversationMessage {
    pub id: String,
    pub role: AiConversationRole,
    pub kind: AiConversationMessageKind,
    pub time: String,
    #[serde(default)]
    pub model: String,
    pub markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalProfile {
    pub id: String,
    pub title: String,
    pub program: String,
    pub args: Vec<String>,
    pub is_default: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayServerInfo {
    pub id: String,
    pub name: String,
    pub session_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForwardInfo {
    pub target_port: u16,
    pub proxy_port: u16,
    pub active_connection_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseAction {
    Move,
    LeftDown,
    LeftUp,
    RightDown,
    RightUp,
    MiddleDown,
    MiddleUp,
    ScrollUp,
    ScrollDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalAttentionKind {
    Confirmation,
    Selection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalAttention {
    pub session_id: SessionId,
    pub title: String,
    pub kind: TerminalAttentionKind,
    pub summary: String,
    pub matched_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalCompletion {
    pub session_id: SessionId,
    pub title: String,
    pub summary: String,
    pub matched_line: String,
}

/// Error codes for protocol errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    UnknownSession,
    SessionAlreadyExists,
    InvalidMessage,
    EncryptionError,
    AuthenticationFailed,
    ServerError,
    RateLimited,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::UnknownSession => write!(f, "Unknown session"),
            ErrorCode::SessionAlreadyExists => write!(f, "Session already exists"),
            ErrorCode::InvalidMessage => write!(f, "Invalid message"),
            ErrorCode::EncryptionError => write!(f, "Encryption error"),
            ErrorCode::AuthenticationFailed => write!(f, "Authentication failed"),
            ErrorCode::ServerError => write!(f, "Server error"),
            ErrorCode::RateLimited => write!(f, "Rate limited"),
        }
    }
}

impl std::error::Error for ErrorCode {}

pub fn hash_secret_key(secret_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_key.trim().as_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(nibble_to_hex(byte >> 4));
        encoded.push(nibble_to_hex(byte & 0x0f));
    }
    encoded
}

pub fn secret_key_challenge_response(secret_key: &str, nonce: &str) -> String {
    secret_key_challenge_response_from_hash(&hash_secret_key(secret_key), nonce)
}

pub fn secret_key_challenge_response_from_hash(secret_key_hash: &str, nonce: &str) -> String {
    hmac_sha256_hex(
        secret_key_hash.trim().as_bytes(),
        format!("vterm-auth-v1:{nonce}").as_bytes(),
    )
}

pub fn verify_secret_key_challenge_response(expected: &str, provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    constant_time_eq(expected.trim().as_bytes(), provided.trim().as_bytes())
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(nibble_to_hex(byte >> 4));
        encoded.push(nibble_to_hex(byte & 0x0f));
    }
    encoded
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 10;

/// Default server port
pub const DEFAULT_SERVER_PORT: u16 = 5153;

/// Maximum serialized protocol message size supported by the encrypted transport
pub const MAX_MESSAGE_SIZE: usize = 10 * 1_048_576;

/// How long per-run log files are kept before a startup cleanup deletes them.
pub const LOG_RETENTION: std::time::Duration = std::time::Duration::from_secs(15 * 24 * 60 * 60);

/// How many of the newest `fatal_*.log` crash logs [`cleanup_old_logs`]
/// always keeps regardless of age: crash forensics must survive even when
/// every panic is older than [`LOG_RETENTION`].
pub const PANIC_LOG_KEEP_COUNT: usize = 30;

/// Channel capacity for [`AsyncLogWriter`]. A backlog anywhere near this
/// means the writer thread is stalled; further messages are then dropped
/// (and counted) instead of buffering unboundedly or blocking the caller.
const LOG_CHANNEL_CAPACITY: usize = 8192;

enum LogMessage {
    Data(Vec<u8>),
    FlushDone(std::sync::mpsc::Sender<()>),
}

/// Non-blocking log writer: formatted log bytes are shipped over a bounded
/// channel to a dedicated writer thread, so the threads that emit log events
/// never wait on file or console I/O.
///
/// Semantics:
/// - **Never blocks.** `write` is a `try_send`; when the channel is full the
///   message is dropped and counted, and the drop count is reported into the
///   sinks on the next flush.
/// - **Ordering.** The channel is FIFO; per-thread order is preserved and
///   interleaving matches arrival order.
/// - **Flush on exit.** `std::process::exit` kills threads without running
///   destructors, so exit paths that need their final log lines on disk must
///   call [`AsyncLogWriter::flush_blocking`] before exiting.
///
/// The type implements [`std::io::Write`] and [`Clone`]; `tracing_subscriber`
/// has a blanket `MakeWriter` impl for `Fn() -> W where W: io::Write`, so a
/// clone closure plugs it into `tracing_subscriber::fmt().with_writer(move ||
/// writer.clone())`.
pub struct AsyncLogWriter {
    tx: std::sync::mpsc::SyncSender<LogMessage>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Clone for AsyncLogWriter {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
        }
    }
}

impl AsyncLogWriter {
    /// Spawn the writer thread serving `sinks`, in order.
    pub fn new(sinks: Vec<Box<dyn std::io::Write + Send>>) -> Self {
        Self::with_capacity(sinks, LOG_CHANNEL_CAPACITY)
    }

    fn with_capacity(sinks: Vec<Box<dyn std::io::Write + Send>>, capacity: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<LogMessage>(capacity);
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_for_worker = dropped.clone();
        std::thread::Builder::new()
            .name("vterm-log-writer".into())
            .spawn(move || log_writer_thread(rx, sinks, dropped_for_worker))
            .expect("failed to spawn the log writer thread");
        Self { tx, dropped }
    }

    /// Total messages dropped because the writer thread could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drain everything sent so far into the sinks and flush them. Bounded
    /// wait: if the writer thread is stalled or dead, returns after ~2s
    /// instead of hanging an exit path.
    pub fn flush_blocking(&self) {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        if self.tx.try_send(LogMessage::FlushDone(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(std::time::Duration::from_secs(2));
        }
    }
}

fn log_writer_thread(
    rx: std::sync::mpsc::Receiver<LogMessage>,
    mut sinks: Vec<Box<dyn std::io::Write + Send>>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    use std::io::Write as _;
    use std::sync::atomic::Ordering;

    fn flush_sinks(
        sinks: &mut [Box<dyn std::io::Write + Send>],
        dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) {
        let dropped = dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let notice = format!(
                "!!! {dropped} log message(s) dropped because the log writer could not keep up\n"
            );
            for sink in sinks.iter_mut() {
                let _ = sink.write_all(notice.as_bytes());
            }
        }
        for sink in sinks.iter_mut() {
            let _ = sink.flush();
        }
    }

    while let Ok(message) = rx.recv() {
        match message {
            LogMessage::Data(bytes) => {
                for sink in sinks.iter_mut() {
                    let _ = sink.write_all(&bytes);
                }
            }
            LogMessage::FlushDone(done) => {
                flush_sinks(&mut sinks, &dropped);
                let _ = done.send(());
            }
        }
    }
    // All senders dropped: last-chance flush.
    flush_sinks(&mut sinks, &dropped);
}

impl std::io::Write for AsyncLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Never block: a full channel drops (and counts) the message
        // instead. Success is reported either way — a stalled sink must not
        // turn into log-call errors upstream.
        match self.tx.try_send(LogMessage::Data(buf.to_vec())) {
            Ok(()) => Ok(buf.len()),
            Err(_) => {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // A no-op so per-event flushes from the fmt layer stay non-blocking;
        // real flushing happens on the writer thread.
        Ok(())
    }
}

/// Windows GUI-subsystem processes (release builds of vterm / vterm-server)
/// have no console, so a console-subsystem child (git, wsl.exe, cmd, …)
/// would allocate a fresh console window that flashes on screen.
/// `CREATE_NO_WINDOW` keeps it hidden; piped stdio is unaffected. No-op off
/// Windows.
pub fn command_no_window(command: &mut std::process::Command) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = command;
    }
}

/// Delete regular files in `dir` whose last modification is older than
/// `max_age`. Best-effort: missing directories and per-file errors are
/// tolerated, with failures only counted in the return value
/// `(removed, failed)`. Only the directory itself is scanned (no recursion),
/// and only regular files are removed — never the file the caller may be
/// actively writing, which by construction is newer than `max_age`.
///
/// `fatal_*.log` crash logs get a two-part policy: a file ages out only when
/// it is older than `max_age` AND newer ones remain — the
/// [`PANIC_LOG_KEEP_COUNT`] newest crash logs are always kept.
pub fn cleanup_old_logs(dir: &std::path::Path, max_age: std::time::Duration) -> (u32, u32) {
    use std::fs;
    use std::time::SystemTime;

    let Ok(entries) = fs::read_dir(dir) else {
        return (0, 0);
    };
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut removed = 0;
    let mut failed = 0;
    let mut fatal_logs: Vec<(std::path::PathBuf, SystemTime)> = Vec::new();
    for entry in entries.flatten() {
        let is_plain_file = entry.file_type().is_ok_and(|ty| ty.is_file());
        if !is_plain_file {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("fatal_") && name.ends_with(".log") {
            if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
                fatal_logs.push((entry.path(), mtime));
            }
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            failed += 1;
            continue;
        };
        // A future mtime (clock skew) keeps the file — only provably old
        // files are deleted.
        if metadata.modified().is_ok_and(|mtime| mtime <= cutoff) {
            match fs::remove_file(entry.path()) {
                Ok(()) => removed += 1,
                Err(_) => failed += 1,
            }
        }
    }
    // Crash logs, newest first: age out only past the kept-newest window.
    fatal_logs.sort_by(|a, b| b.1.cmp(&a.1));
    for (path, mtime) in fatal_logs.into_iter().skip(PANIC_LOG_KEEP_COUNT) {
        if mtime <= cutoff {
            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(_) => failed += 1,
            }
        }
    }
    (removed, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId::from_bytes([0; 16]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 8);
    }

    #[test]
    fn cleanup_old_logs_removes_files_past_max_age() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.log"), b"x").unwrap();
        std::fs::write(dir.path().join("b.log"), b"x").unwrap();

        // Files written before the call are older than a zero max age, so
        // both go; their mtimes precede the cutoff sampled at entry.
        let (removed, failed) = cleanup_old_logs(dir.path(), std::time::Duration::ZERO);
        assert_eq!((removed, failed), (2, 0));
        assert!(!dir.path().join("a.log").exists());
        assert!(!dir.path().join("b.log").exists());
    }

    #[test]
    fn cleanup_old_logs_keeps_files_within_max_age() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.log"), b"x").unwrap();

        let (removed, failed) = cleanup_old_logs(
            dir.path(),
            std::time::Duration::from_secs(365 * 24 * 60 * 60),
        );
        assert_eq!((removed, failed), (0, 0));
        assert!(dir.path().join("a.log").exists());
    }

    #[test]
    fn cleanup_old_logs_ignores_directories_and_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();

        let (removed, failed) = cleanup_old_logs(dir.path(), std::time::Duration::ZERO);
        assert_eq!((removed, failed), (0, 0));
        assert!(dir.path().join("nested").exists());

        let missing = dir.path().join("does-not-exist");
        assert_eq!(
            cleanup_old_logs(&missing, std::time::Duration::ZERO),
            (0, 0)
        );
    }

    #[test]
    fn cleanup_old_logs_keeps_the_newest_fatal_logs_regardless_of_age() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(PANIC_LOG_KEEP_COUNT + 5) {
            std::fs::write(dir.path().join(format!("fatal_x_panic_{i:03}.log")), b"x").unwrap();
        }
        std::fs::write(dir.path().join("run.log"), b"x").unwrap();

        // Zero max age: every file is provably old. The regular log goes;
        // exactly PANIC_LOG_KEEP_COUNT crash logs survive.
        let (removed, failed) = cleanup_old_logs(dir.path(), std::time::Duration::ZERO);
        assert_eq!(failed, 0);
        assert_eq!(removed, 6); // run.log + 5 overflow fatal logs
        assert!(!dir.path().join("run.log").exists());
        let remaining = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("fatal_"))
            .count();
        assert_eq!(remaining, PANIC_LOG_KEEP_COUNT);

        // A generous max age keeps even the overflow files.
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(PANIC_LOG_KEEP_COUNT + 5) {
            std::fs::write(dir.path().join(format!("fatal_x_panic_{i:03}.log")), b"x").unwrap();
        }
        let (removed, failed) = cleanup_old_logs(
            dir.path(),
            std::time::Duration::from_secs(365 * 24 * 60 * 60),
        );
        assert_eq!((removed, failed), (0, 0));
    }

    #[test]
    fn async_log_writer_delivers_in_order_and_flushes() {
        use std::io::Write;

        struct SharedSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for SharedSink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut writer = AsyncLogWriter::new(vec![Box::new(SharedSink(sink.clone()))]);
        writer.write_all(b"hello ").unwrap();
        writer.write_all(b"world\n").unwrap();
        // FIFO: both Data messages precede the flush marker, so they are on
        // the sink once flush_blocking returns.
        writer.flush_blocking();
        assert_eq!(&*sink.lock().unwrap(), b"hello world\n");
    }

    #[test]
    fn async_log_writer_never_blocks_when_sinks_stall() {
        use std::io::Write;
        use std::time::{Duration, Instant};

        // A sink that stalls on every write; with capacity 1 the worker can
        // never keep up, so most messages must be dropped — and every
        // write() must return immediately regardless.
        struct StalledSink;
        impl std::io::Write for StalledSink {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(5));
                Ok(0)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = AsyncLogWriter::with_capacity(vec![Box::new(StalledSink)], 1);
        let start = Instant::now();
        for i in 0..100u32 {
            writer.write_all(format!("line {i}\n").as_bytes()).unwrap();
        }
        let elapsed = start.elapsed();
        // 100 stalled sink writes take >= 500ms of writer-thread time; the
        // emitting side must have returned far sooner than that.
        assert!(
            elapsed < Duration::from_millis(400),
            "write() blocked: {elapsed:?}"
        );
        assert!(writer.dropped() > 0);
    }

    #[test]
    fn test_terminal_size_default() {
        let size = TerminalSize::default();
        assert_eq!(size.rows, 24);
        assert_eq!(size.cols, 80);
    }

    #[test]
    fn test_hash_secret_key() {
        assert_eq!(
            hash_secret_key("abcdefghijkl"),
            "d682ed4ca4d989c134ec94f1551e1ec580dd6d5a6ecde9f3d35e6e4a717fbde4"
        );
    }

    #[test]
    fn test_secret_key_challenge_response_uses_hash_key() {
        let nonce = "challenge";
        let from_secret = secret_key_challenge_response("abcdefghijkl", nonce);
        let from_hash = secret_key_challenge_response_from_hash(
            "d682ed4ca4d989c134ec94f1551e1ec580dd6d5a6ecde9f3d35e6e4a717fbde4",
            nonce,
        );

        assert_eq!(from_secret, from_hash);
        assert!(verify_secret_key_challenge_response(
            &from_secret,
            Some(&from_hash)
        ));
        assert!(!verify_secret_key_challenge_response(
            &from_secret,
            Some("invalid")
        ));
    }

    #[test]
    fn test_cell_default() {
        let cell = Cell::default();
        assert_eq!(cell.character, ' ');
        assert_eq!(cell.fg_color, Color::Default);
        assert_eq!(cell.bg_color, Color::Default);
    }

    #[test]
    fn test_cell_attributes() {
        let attrs = CellAttributes::BOLD | CellAttributes::UNDERLINE;
        assert!(attrs.contains(CellAttributes::BOLD));
        assert!(attrs.contains(CellAttributes::UNDERLINE));
        assert!(!attrs.contains(CellAttributes::ITALIC));
    }

    #[test]
    fn test_serialization() {
        let size = TerminalSize::new(30, 100);
        let serialized = serde_json::to_string(&size).unwrap();
        let deserialized: TerminalSize = serde_json::from_str(&serialized).unwrap();
        assert_eq!(size, deserialized);
    }

    /// The MCP command target rides the known-app list: new clients must read
    /// it when present, and default to `terminal` when an older server omits
    /// the field entirely.
    #[test]
    fn test_known_app_info_serializes_mcp_command_target() {
        let terminal = KnownAppInfo {
            executable: "claude".to_string(),
            display_name: "Claude Code".to_string(),
            mcp_command_target: McpCommandTarget::Terminal,
        };
        let in_app = KnownAppInfo {
            executable: "kimi".to_string(),
            display_name: "Kimi Code".to_string(),
            mcp_command_target: McpCommandTarget::InApp,
        };

        let terminal_json = serde_json::to_string(&terminal).unwrap();
        assert!(terminal_json.contains(r#""mcp_command_target":"terminal""#));
        let in_app_json = serde_json::to_string(&in_app).unwrap();
        assert!(in_app_json.contains(r#""mcp_command_target":"in_app""#));
        assert_eq!(
            serde_json::from_str::<KnownAppInfo>(&in_app_json).unwrap(),
            in_app
        );

        // An older server that never sends the field falls back to terminal.
        let legacy = r#"{"executable":"kimi","display_name":"Kimi Code"}"#;
        let legacy: KnownAppInfo = serde_json::from_str(legacy).unwrap();
        assert_eq!(legacy.mcp_command_target, McpCommandTarget::Terminal);
    }

    #[test]
    fn test_file_list_item_serialization_omits_false_is_dir() {
        let file_json =
            serde_json::to_string(&FileListItem::file("Cargo.toml".to_string())).unwrap();
        let dir_json = serde_json::to_string(&FileListItem::directory("src".to_string())).unwrap();

        assert_eq!(file_json, r#"{"name":"Cargo.toml"}"#);
        assert_eq!(dir_json, r#"{"name":"src","is_dir":true}"#);
    }
}
