//! Boot read-ahead (`SCARLETT_PREFETCH=1`, or `SCARLETT_PREFETCH=1`; off by
//! default). A boot writes down which parts of which files the title read
//! (DirectStorage requests and its own `ReadFile` calls), in the order it
//! first touched them, 1 MiB at a time. The next boot reads those parts on
//! a few threads of ours as soon as the title opens its first DirectStorage
//! file, through the host's file cache, so that the title's own reads find
//! them in memory instead of waiting on the disk one at a time.
//!
//! Only hints: nothing the title is given changes, and a list that is stale
//! or names a file that is gone costs a wasted read at most.
//!
//! * The list: `<SCARLETT_CACHE_DIR>\prefetch\boot-reads.txt`, or
//!   `SCARLETT_PREFETCH_LIST=<file>`. Lines `path<TAB>first MiB<TAB>MiBs`.
//!   Rewritten from this boot's reads every 30 s for the first
//!   `SCARLETT_PREFETCH_SECS` seconds (default 300).
//! * `SCARLETT_PREFETCH_MB` (default 6144): at most this much is read ahead.
//! * `SCARLETT_PREFETCH_THREADS` (default 4): threads reading ahead, below
//!   normal priority.
//! * `SCARLETT_PREFETCH_RECORD_ONLY=1`: write the list, read nothing ahead.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Parts are 1 MiB.
const SHIFT: u32 = 20;
/// Runs longer than this are split, so several threads share a big file.
const PIECE: u64 = 16;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn number(name: &str, default: u64) -> u64 {
    var(name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Whether the switch is on.
pub(crate) fn on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| var("SCARLETT_PREFETCH").is_some_and(|v| v == "1"))
}

fn list_path() -> Option<PathBuf> {
    if let Some(p) = var("SCARLETT_PREFETCH_LIST") {
        return Some(PathBuf::from(p));
    }
    let dir = std::env::var_os("SCARLETT_CACHE_DIR")?;
    Some(PathBuf::from(dir).join("prefetch").join("boot-reads.txt"))
}

#[derive(Default)]
struct Recorder {
    paths: Vec<String>,
    by_path: HashMap<String, u32>,
    /// Our DirectStorage file objects and the title's handles, by address.
    keys: HashMap<usize, Option<u32>>,
    seen: HashSet<(u32, u64)>,
    order: Vec<(u32, u64)>,
    /// Reads noted since the last write of the list.
    fresh: bool,
}

struct State {
    started: Instant,
    window: Duration,
    recorder: Mutex<Recorder>,
}

fn state() -> &'static State {
    static STATE: OnceLock<State> = OnceLock::new();
    STATE.get_or_init(|| State {
        started: Instant::now(),
        window: Duration::from_secs(number("SCARLETT_PREFETCH_SECS", 300)),
        recorder: Mutex::new(Recorder::default()),
    })
}

/// At the title's first DirectStorage file: reads the last boot's list
/// ahead, and starts writing this boot's.
pub(crate) fn start() {
    if !on() {
        return;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let state = state();
        let Some(path) = list_path() else {
            tracing::warn!("prefetch: no list (set SCARLETT_CACHE_DIR or SCARLETT_PREFETCH_LIST); off");
            return;
        };
        if var("SCARLETT_PREFETCH_RECORD_ONLY").is_none_or(|v| v != "1") {
            match std::fs::read_to_string(&path) {
                Ok(text) => read_ahead(parse(&text)),
                Err(e) => tracing::info!(path = %path.display(), %e, "prefetch: no list from an earlier boot yet"),
            }
        }
        let window = state.window;
        let _ = std::thread::Builder::new().name("prefetch list".into()).spawn(move || {
            let mut at = Duration::ZERO;
            while at < window {
                at = (at + Duration::from_secs(30)).min(window);
                std::thread::sleep(at.saturating_sub(state.started.elapsed()));
                if let Err(e) = write_list(&path) {
                    tracing::warn!(path = %path.display(), %e, "prefetch: the list was not written");
                }
            }
        });
    });
}

/// Names a DirectStorage file object (`key`) by its host path.
pub(crate) fn file_opened(key: usize, file: &std::fs::File) {
    if !on() {
        return;
    }
    let path = final_path(file);
    let mut r = lock();
    let id = path.map(|p| r.id(p));
    r.keys.insert(key, id);
}

/// A read of `len` bytes at `offset` of the file `key` names.
pub(crate) fn read(key: usize, offset: u64, len: u64) {
    if !on() || state().started.elapsed() >= state().window {
        return;
    }
    let mut r = lock();
    if let Some(Some(id)) = r.keys.get(&key).copied() {
        r.note(id, offset, len);
    }
}

/// A read of the title's own `ReadFile`: `offset` from its OVERLAPPED, or
/// the handle's position.
pub(crate) fn title_read(handle: *mut std::ffi::c_void, overlapped: *const u64, len: u32) {
    if !on() || len == 0 || state().started.elapsed() >= state().window {
        return;
    }
    let offset = if overlapped.is_null() {
        let mut at = 0i64;
        // SAFETY: asks a handle the title passed for its position; moves nothing.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::SetFilePointerEx(handle, 0, &mut at, 1)
        } != 0;
        if !ok {
            return;
        }
        at as u64
    } else {
        // SAFETY: OVERLAPPED's Offset/OffsetHigh are its third u64 (after Internal, InternalHigh).
        unsafe { overlapped.add(2).read_unaligned() }
    };
    let key = handle as usize;
    let mut r = lock();
    let id = match r.keys.get(&key) {
        Some(id) => *id,
        None => {
            // SAFETY: borrowed for the query only; the title keeps owning it.
            let file = std::mem::ManuallyDrop::new(unsafe {
                <std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(handle)
            });
            let id = final_path(&file).filter(|p| !p.to_ascii_lowercase().contains("\\scarlett\\data\\")).map(|p| r.id(p));
            r.keys.insert(key, id);
            id
        }
    };
    if let Some(id) = id {
        r.note(id, offset, u64::from(len));
    }
}

fn lock() -> std::sync::MutexGuard<'static, Recorder> {
    state().recorder.lock().unwrap_or_else(|e| e.into_inner())
}

impl Recorder {
    fn id(&mut self, path: String) -> u32 {
        if let Some(&id) = self.by_path.get(&path) {
            return id;
        }
        let id = self.paths.len() as u32;
        self.by_path.insert(path.clone(), id);
        self.paths.push(path);
        id
    }

    fn note(&mut self, id: u32, offset: u64, len: u64) {
        let (first, last) = (offset >> SHIFT, (offset + len.max(1) - 1) >> SHIFT);
        for part in first..=last {
            if self.seen.insert((id, part)) {
                self.order.push((id, part));
                self.fresh = true;
            }
        }
    }

    /// The parts as runs, in first-touch order.
    fn runs(&self) -> Vec<(u32, u64, u64)> {
        let mut runs: Vec<(u32, u64, u64)> = Vec::new();
        for &(id, part) in &self.order {
            match runs.last_mut() {
                Some((i, first, n)) if *i == id && *first + *n == part => *n += 1,
                _ => runs.push((id, part, 1)),
            }
        }
        runs
    }
}

fn write_list(path: &std::path::Path) -> std::io::Result<()> {
    let (text, parts) = {
        let mut r = lock();
        if !std::mem::take(&mut r.fresh) {
            return Ok(());
        }
        let mut text = String::new();
        for (id, first, n) in r.runs() {
            text.push_str(&format!("{}\t{first}\t{n}\n", r.paths[id as usize]));
        }
        (text, r.order.len())
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::File::create(&tmp)?.write_all(text.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    tracing::info!(path = %path.display(), mb = parts, "prefetch: list written");
    Ok(())
}

fn parse(text: &str) -> Vec<(String, u64, u64)> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let path = f.next()?.to_string();
            let first = f.next()?.parse().ok()?;
            let n = f.next()?.parse().ok()?;
            (!path.is_empty() && n > 0).then_some((path, first, n))
        })
        .collect()
}

/// Splits the runs into pieces, up to the cap, and starts the threads.
fn read_ahead(runs: Vec<(String, u64, u64)>) {
    let cap = number("SCARLETT_PREFETCH_MB", 6144);
    let mut pieces = VecDeque::new();
    let mut total = 0u64;
    'all: for (path, first, n) in runs {
        let mut at = first;
        while at < first + n {
            let take = PIECE.min(first + n - at).min(cap - total);
            if take == 0 {
                break 'all;
            }
            pieces.push_back((path.clone(), at, take));
            at += take;
            total += take;
        }
    }
    if pieces.is_empty() {
        return;
    }
    let threads = number("SCARLETT_PREFETCH_THREADS", 4).clamp(1, 32) as usize;
    tracing::info!(mb = total, pieces = pieces.len(), threads, "prefetch: reading ahead");
    let work: &'static Mutex<(VecDeque<(String, u64, u64)>, u64, usize)> =
        Box::leak(Box::new(Mutex::new((pieces, 0, threads))));
    let started = Instant::now();
    for i in 0..threads {
        let _ = std::thread::Builder::new().name(format!("prefetch {i}")).spawn(move || {
            // SAFETY: lowers our own thread's priority.
            unsafe {
                use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL};
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            }
            let mut buffer = vec![0u8; 1 << SHIFT];
            let mut open: Option<(String, std::fs::File)> = None;
            loop {
                let Some((path, first, n)) = work.lock().unwrap_or_else(|e| e.into_inner()).0.pop_front() else {
                    break;
                };
                if open.as_ref().is_none_or(|(p, _)| *p != path) {
                    open = open_shared(&path).map(|f| (path.clone(), f));
                }
                let Some((_, file)) = &open else { continue };
                let mut read = 0u64;
                for part in first..first + n {
                    match std::os::windows::fs::FileExt::seek_read(file, &mut buffer, part << SHIFT) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => read += k as u64,
                    }
                }
                work.lock().unwrap_or_else(|e| e.into_inner()).1 += read;
            }
            let mut w = work.lock().unwrap_or_else(|e| e.into_inner());
            w.2 -= 1;
            if w.2 == 0 {
                tracing::info!(
                    mb = w.1 >> SHIFT,
                    secs = format_args!("{:.1}", started.elapsed().as_secs_f64()),
                    "prefetch: read ahead"
                );
            }
        });
    }
}

fn open_shared(path: &str) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .ok()
}

/// The host path of an open file (`\\?\` dropped).
fn final_path(file: &std::fs::File) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    let mut buffer = vec![0u16; 1024];
    // SAFETY: an open handle; the buffer holds `len` u16s.
    let n = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if n == 0 || n >= buffer.len() {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..n]);
    Some(path.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_become_runs_in_first_touch_order() {
        let mut r = Recorder::default();
        let a = r.id("a".into());
        let b = r.id("b".into());
        r.note(a, 0, 3 << SHIFT);
        r.note(b, 5 << SHIFT, 1);
        r.note(a, (2 << SHIFT) + 7, 2 << SHIFT); // parts 2 (seen), 3, 4
        assert_eq!(r.runs(), vec![(a, 0, 3), (b, 5, 1), (a, 3, 2)]);
        let text: String = r.runs().iter().map(|(i, f, n)| format!("{}\t{f}\t{n}\n", r.paths[*i as usize])).collect();
        assert_eq!(parse(&text), vec![("a".into(), 0, 3), ("b".into(), 5, 1), ("a".into(), 3, 2)]);
        assert!(parse("bad line\nx\t1\n\t1\t1\n").is_empty());
    }

    #[test]
    fn a_list_reads_its_file_into_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, vec![7u8; 3 << SHIFT]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let host = final_path(&file).unwrap();
        assert!(open_shared(&host).is_some());
    }
}
