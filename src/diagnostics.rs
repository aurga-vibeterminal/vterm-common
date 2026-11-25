//! Process-level crash forensics shared by every vterm binary: a panic hook
//! and a native crash handler that both capture diagnostics into
//! `fatal_*.log` files next to the binary's regular logs.
//!
//! The handlers are process-global singletons, so this is installed
//! explicitly — exactly once, early in `main()` — rather than as a side
//! effect of linking the crate:
//!
//! ```no_run
//! vterm_common::diagnostics::install_crash_handlers(
//!     log_dir.clone(),
//!     env!("CARGO_PKG_VERSION"),
//!     false, // let panics unwind instead of aborting the process
//! );
//! ```
//!
//! Tracing setup is intentionally *not* part of this module: each binary has
//! its own filter conventions and log-directory quirks.

use std::backtrace::Backtrace;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use chrono::Local;

/// Where `fatal_*.log` files are written; set by [`install_crash_handlers`]
/// before any handler that might need it.
static CRASH_LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Version string reported in fatal logs. Lives in the caller (each binary
/// passes its own `env!("CARGO_PKG_VERSION")`) because `env!` would otherwise
/// resolve to *this* crate's version.
static APP_VERSION: OnceLock<&'static str> = OnceLock::new();

/// Whether a panic aborts the process after its fatal log is written.
static ABORT_ON_PANIC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install the panic hook and the platform native crash handler.
///
/// `abort_on_panic` selects the panic policy: GUI binaries pass `true` (a
/// panicking UI is unusable anyway, and aborting routes through the native
/// crash handler for a second, signal-level report); server binaries pass
/// `false` so Tokio isolates the panicking task and live sessions survive
/// one session's bug.
///
/// Safe to call more than once — only the first call takes effect.
pub fn install_crash_handlers(log_dir: PathBuf, app_version: &'static str, abort_on_panic: bool) {
    let _ = CRASH_LOG_DIR.set(log_dir);
    let _ = APP_VERSION.set(app_version);
    ABORT_ON_PANIC.store(abort_on_panic, std::sync::atomic::Ordering::Relaxed);
    install_panic_hook();
    install_native_crash_handler();
}

/// Capture panics (message, location, thread, backtrace) into a
/// `fatal_*_panic_*.log` file next to the regular run logs.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");

        let mut details = String::new();
        let _ = writeln!(
            details,
            "thread: {} ({:?})",
            thread.name().unwrap_or("<unnamed>"),
            thread.id()
        );
        if let Some(location) = info.location() {
            let _ = writeln!(
                details,
                "location: {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        }
        let _ = writeln!(details, "message: {payload}");
        let _ = writeln!(details, "backtrace:\n{}", Backtrace::force_capture());

        let fatal_log = write_fatal_log("panic", &details);
        eprintln!("PANIC: {info:?}; fatal_log={fatal_log:?}");
        if ABORT_ON_PANIC.load(std::sync::atomic::Ordering::Relaxed) {
            // abort() raises SIGABRT, which the unix crash handler reports
            // as a second, signal-level fatal log before the core dump.
            std::process::abort();
        }
    }));
}

fn write_fatal_log(kind: &str, details: &str) -> Option<PathBuf> {
    let log_dir = CRASH_LOG_DIR.get()?;
    let path = log_dir.join(format!(
        "fatal_{}_{}_{}.log",
        file_timestamp(),
        kind,
        std::process::id()
    ));
    let mut file = open_log_file(&path).ok()?;
    let _ = writeln!(
        file,
        "timestamp: {}\nprocess_id: {}\nversion: {}\nos: {}\narch: {}\nkind: {}\n{}",
        Local::now().to_rfc3339(),
        std::process::id(),
        APP_VERSION.get().copied().unwrap_or("<unknown>"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        kind,
        details
    );
    let _ = file.flush();
    Some(path)
}

fn open_log_file(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

fn file_timestamp() -> String {
    Local::now().format("%Y-%m-%d_%H-%M-%S_%3f").to_string()
}

#[cfg(target_os = "windows")]
fn install_native_crash_handler() {
    use windows_sys::Win32::System::Diagnostics::Debug::SetUnhandledExceptionFilter;

    unsafe {
        SetUnhandledExceptionFilter(Some(windows_unhandled_exception));
    }
}

#[cfg(unix)]
fn install_native_crash_handler() {
    unix::install();
}

/// Fatal-signal handling for Linux/macOS. Registers `SA_SIGINFO` handlers for
/// the synchronous fault signals (plus SIGABRT) on an alternate signal stack,
/// writes a `fatal_*` log next to the tracing logs, then re-raises the signal
/// with the default disposition so the OS still produces a core dump.
///
/// Stack-safety constraints discovered while testing:
///
/// - Rust std installs its own 8 KiB altstack (`SIGSTKSZ`) on every thread it
///   spawns, for stack-overflow detection. When our handler runs on such a
///   thread it lands on that tiny stack, and the std `Backtrace` symbolizer
///   (addr2line/gimli) needs far more than 8 KiB — it re-faults and the
///   process dies with no report. The handler therefore checks the current
///   altstack size and skips the backtrace when there is too little room;
///   the report then contains signal/fault-address/thread only (and the
///   re-raised fault still yields a core dump for gdb).
/// - The thread that calls [`install_crash_handlers`] (normally the main
///   thread) gets a 256 KiB mmap'd altstack with a guard page, so its crashes
///   always produce a full symbolized backtrace.
/// - The symbolizer is pre-warmed at install time so its lazy statics and
///   global cache are initialized before a signal can interrupt them
///   half-built.
#[cfg(unix)]
mod unix {
    use std::backtrace::Backtrace;
    use std::fmt::Write as _;
    use std::mem::MaybeUninit;

    use super::write_fatal_log;

    /// Signals that indicate the process state is already doomed; handling
    /// them only serves to capture diagnostics before the core dump.
    const FATAL_SIGNALS: &[libc::c_int] = &[
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGILL,
        libc::SIGFPE,
        libc::SIGABRT,
    ];

    /// Alternate stack for the installing thread. Backtrace symbolization can
    /// use tens of KiB; 256 KiB leaves ample headroom even for deep GL/X11
    /// stacks. Virtual memory only — untouched pages are never committed.
    const ALT_STACK_SIZE: usize = 256 * 1024;

    /// Minimum altstack size on which backtrace symbolization is attempted.
    /// Below this (e.g. std's 8 KiB per-thread altstack) the handler writes a
    /// minimal report instead of risking a re-fault inside the symbolizer.
    const MIN_SYMBOLIZE_STACK: usize = 64 * 1024;

    pub fn install() {
        // Pre-warm the backtrace machinery (lazy statics, global symbol
        // cache) before any signal can interrupt it half-initialized.
        let _ = format!("{}", Backtrace::force_capture());

        install_alt_stack();
        unsafe {
            let mut action: libc::sigaction = MaybeUninit::zeroed().assume_init();
            action.sa_sigaction = fatal_signal_handler as *const () as libc::sighandler_t;
            // Block every signal while the handler runs: a second fault
            // mid-report would otherwise recurse.
            libc::sigfillset(&mut action.sa_mask);
            // SA_RESETHAND restores SIG_DFL on handler entry, so the trailing
            // re-raise dies normally (core dump), and a fault *inside* the
            // handler cannot loop.
            action.sa_flags =
                libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESETHAND | libc::SA_NODEFER;
            for &sig in FATAL_SIGNALS {
                if libc::sigaction(sig, &action, std::ptr::null_mut()) != 0 {
                    eprintln!(
                        "failed to install crash handler for signal {sig}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }

    /// Registers a guard-paged 256 KiB altstack on the calling thread.
    /// Threads spawned afterwards keep whatever std gives them; the handler
    /// adapts at fault time.
    fn install_alt_stack() {
        unsafe {
            let page = page_size();
            let total = ALT_STACK_SIZE + page;
            let base = libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if base == libc::MAP_FAILED {
                return;
            }
            // Guard page at the bottom: an overflowing handler faults cleanly
            // (and SA_RESETHAND turns that into a plain core dump) instead of
            // silently corrupting adjacent mappings.
            if libc::mprotect(base, page, libc::PROT_NONE) != 0 {
                libc::munmap(base, total);
                return;
            }
            let stack = libc::stack_t {
                ss_sp: base.add(page),
                ss_flags: 0,
                ss_size: ALT_STACK_SIZE,
            };
            if libc::sigaltstack(&stack, std::ptr::null_mut()) != 0 {
                libc::munmap(base, total);
            }
            // On success the kernel owns the mapping until process exit.
        }
    }

    /// True when the handler can afford backtrace symbolization: either no
    /// altstack is registered (we are on the thread's normal stack) or the
    /// altstack is large enough. A bare `sigaltstack` query is a thin syscall
    /// with no userspace state, so it is safe to call here.
    fn stack_room_for_backtrace() -> bool {
        unsafe {
            let mut stack: libc::stack_t = MaybeUninit::zeroed().assume_init();
            if libc::sigaltstack(std::ptr::null(), &mut stack) != 0 {
                return false;
            }
            (stack.ss_flags & libc::SS_DISABLE) != 0 || stack.ss_size >= MIN_SYMBOLIZE_STACK
        }
    }

    fn page_size() -> usize {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    unsafe extern "C" fn fatal_signal_handler(
        sig: libc::c_int,
        info: *mut libc::siginfo_t,
        _context: *mut libc::c_void,
    ) {
        // None of this is strictly async-signal-safe (thread-locals,
        // allocation, backtrace capture, file I/O), and cannot be made so
        // while still producing a useful report. SA_RESETHAND bounds the
        // worst case: if reporting itself faults, the process simply dies
        // with the original disposition instead of hanging or looping.
        let kind = signal_name(sig);
        let fault_address = if info.is_null() {
            None
        } else {
            // SAFETY: si_addr is valid for the fault signals we handle.
            Some(unsafe { (*info).si_addr() })
        };

        let thread = std::thread::current();
        let mut details = String::new();
        let _ = writeln!(details, "signal: {sig} ({kind})");
        let _ = writeln!(details, "fault_address: {fault_address:?}");
        let _ = writeln!(
            details,
            "thread: {} ({:?})",
            thread.name().unwrap_or("<unnamed>"),
            thread.id()
        );
        if stack_room_for_backtrace() {
            let _ = writeln!(details, "backtrace:\n{}", Backtrace::force_capture());
        } else {
            let _ = writeln!(
                details,
                "backtrace: <skipped: altstack too small; use the core dump>"
            );
        }

        let fatal_log = write_fatal_log(kind, &details);
        eprintln!("FATAL SIGNAL: {kind} (sig={sig}) fault_address={fault_address:?}; fatal_log={fatal_log:?}");

        // The handler's full block mask is still active, so a raised signal
        // would only go pending. Unblock this signal first, then re-raise:
        // SA_RESETHAND already restored SIG_DFL, so the process dies with the
        // original disposition and the kernel dumps a core.
        unsafe {
            let mut set: libc::sigset_t = MaybeUninit::zeroed().assume_init();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, sig);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::raise(sig);
        }
        // If the raise somehow returns (ignored disposition), leave no survivor.
        std::process::abort();
    }

    fn signal_name(sig: libc::c_int) -> &'static str {
        match sig {
            libc::SIGSEGV => "sigsegv",
            libc::SIGBUS => "sigbus",
            libc::SIGILL => "sigill",
            libc::SIGFPE => "sigfpe",
            libc::SIGABRT => "sigabrt",
            _ => "signal",
        }
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_unhandled_exception(
    exception_pointers: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_EXECUTE_HANDLER;

    let details = if exception_pointers.is_null()
        || unsafe { (*exception_pointers).ExceptionRecord.is_null() }
    {
        "exception_code: <unavailable>\nexception_address: <unavailable>".to_string()
    } else {
        let record = unsafe { &*(*exception_pointers).ExceptionRecord };
        format!(
            "exception_code: 0x{:08X}\nexception_flags: 0x{:08X}\nexception_address: {:?}",
            record.ExceptionCode as u32, record.ExceptionFlags, record.ExceptionAddress
        )
    };
    // The worker's stdout/stderr may be the only channel that survives when
    // the log dir is unreachable (winlogon-persona workers); mirror there.
    eprintln!("FATAL EXCEPTION:\n{details}");
    let _ = write_fatal_log("exception", &details);
    EXCEPTION_EXECUTE_HANDLER
}
