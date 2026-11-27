//! Who waits on what: `SCARLETT_WAIT_LOG=<ms>` (or `SCARLETT_WAIT_LOG`;
//! `1` is 100) puts timing shims under the title's blocking calls (`Sleep`,
//! `WaitForSingleObject[Ex]`, `WaitForMultipleObjects`) and, every five
//! seconds, logs the call sites whose threads stood blocked for at least
//! that long in the window: how many threads, how many waits, the time, the
//! longest wait and what it was on (handle, timeout), and the title code
//! that called (`module+rva`, innermost first). A wait still going on is
//! counted by its age, so a thread parked for a minute on one event shows
//! from its first window on, not when it wakes.
//!
//! Unset, no shim is bound: the title calls the host's functions as before.
#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use windows_sys::Win32::System::Threading as host;

use crate::{HleExport, hle_export};

/// Callers kept of each wait.
const CALLERS: usize = 4;
/// How often the report is written.
const WINDOW: Duration = Duration::from_secs(5);
/// Lines per report.
const LINES: usize = 48;

/// The threshold in milliseconds, if the switch is on.
pub(crate) fn threshold_ms() -> Option<u64> {
    static ASKED: OnceLock<Option<u64>> = OnceLock::new();
    *ASKED.get_or_init(|| asked(&std::env::var("SCARLETT_WAIT_LOG").ok()?))
}

/// What the switch's value says: off for nothing, `0` or junk; 100 ms for `1`.
fn asked(value: &str) -> Option<u64> {
    match value.trim().parse::<u64>().ok()? {
        0 => None,
        1 => Some(100),
        ms => Some(ms),
    }
}

/// The shims, to be bound in place of the host's functions.
pub(crate) fn exports() -> Vec<HleExport> {
    if threshold_ms().is_none() {
        return Vec::new();
    }
    vec![
        hle_export!(Sleep),
        hle_export!(WaitForSingleObject),
        hle_export!(WaitForSingleObjectEx),
        hle_export!(WaitForMultipleObjects),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u32)]
enum Api {
    Sleep = 1,
    Single = 2,
    SingleEx = 3,
    Multiple = 4,
}

impl Api {
    fn name(self) -> &'static str {
        match self {
            Api::Sleep => "Sleep",
            Api::Single => "WaitForSingleObject",
            Api::SingleEx => "WaitForSingleObjectEx",
            Api::Multiple => "WaitForMultipleObjects",
        }
    }

    fn of(n: u32) -> Option<Api> {
        [Api::Sleep, Api::Single, Api::SingleEx, Api::Multiple]
            .into_iter()
            .find(|a| *a as u32 == n)
    }
}

/// Where a wait is made: the call and the title's return addresses.
type Site = (Api, [usize; CALLERS]);

#[derive(Default, Clone, Copy)]
struct Sum {
    waits: u64,
    micros: u64,
    longest_micros: u64,
    /// Of the longest: the handle (or count) and the timeout.
    object: usize,
    timeout: u32,
}

impl Sum {
    /// A wait that ended: its time since the last report, and in all.
    fn add(&mut self, micros: u64, whole: u64, object: usize, timeout: u32) {
        self.waits += 1;
        self.micros += micros;
        if whole >= self.longest_micros {
            (self.longest_micros, self.object, self.timeout) = (whole, object, timeout);
        }
    }
}

/// One thread's wait now, read by the reporter while the thread sleeps.
#[derive(Default)]
struct Slot {
    thread: u32,
    /// Microseconds since [`epoch`] at which the wait began; 0 for none.
    since: AtomicU64,
    api: AtomicU32,
    object: AtomicUsize,
    timeout: AtomicU32,
    callers: [AtomicUsize; CALLERS],
    /// Waits ended since the last report.
    done: Mutex<HashMap<Site, Sum>>,
}

/// When the last report was written, as [`now_micros`].
static LAST_REPORT: AtomicU64 = AtomicU64::new(0);

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_micros() -> u64 {
    epoch().elapsed().as_micros() as u64 + 1
}

fn slots() -> &'static Mutex<Vec<Arc<Slot>>> {
    static SLOTS: OnceLock<Mutex<Vec<Arc<Slot>>>> = OnceLock::new();
    SLOTS.get_or_init(|| {
        std::thread::Builder::new()
            .name("wait log".into())
            .spawn(report)
            .ok();
        Mutex::new(Vec::new())
    })
}

thread_local! {
    static SLOT: Arc<Slot> = {
        // SAFETY: no arguments.
        let slot = Arc::new(Slot { thread: unsafe { host::GetCurrentThreadId() }, ..Slot::default() });
        slots().lock().unwrap_or_else(|e| e.into_inner()).push(slot.clone());
        slot
    };
}

/// Runs `wait` with the thread's slot saying what it waits on.
#[inline(always)]
fn timed<R>(api: Api, object: usize, timeout: u32, wait: impl FnOnce() -> R) -> R {
    // A wait that cannot block is not looked at.
    if timeout == 0 {
        return wait();
    }
    let mut callers = [std::ptr::null_mut::<c_void>(); CALLERS];
    // SAFETY: fills at most `CALLERS` return addresses, above the shim's own.
    unsafe {
        RtlCaptureStackBackTrace(
            1,
            CALLERS as u32,
            callers.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    let callers = callers.map(|c| c as usize);
    let Ok(slot) = SLOT.try_with(Arc::clone) else {
        return wait();
    };
    for (to, from) in slot.callers.iter().zip(callers) {
        to.store(from, Relaxed);
    }
    slot.api.store(api as u32, Relaxed);
    slot.object.store(object, Relaxed);
    slot.timeout.store(timeout, Relaxed);
    let began = now_micros();
    slot.since.store(began, Relaxed);
    let result = wait();
    slot.since.store(0, Relaxed);
    // The reports before this one counted the wait up to the last of them,
    // as one going on; what is left is counted here.
    let ended = now_micros();
    slot.done
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry((api, callers))
        .or_default()
        .add(
            ended.saturating_sub(began.max(LAST_REPORT.load(Relaxed))),
            ended.saturating_sub(began),
            object,
            timeout,
        );
    result
}

pub extern "system" fn Sleep(ms: u32) {
    // SAFETY: the host's call.
    timed(Api::Sleep, 0, ms, || unsafe { host::Sleep(ms) });
}

pub extern "system" fn WaitForSingleObject(handle: HANDLE, ms: u32) -> u32 {
    // SAFETY: the title's handle, passed on as it is.
    timed(Api::Single, handle as usize, ms, || unsafe {
        host::WaitForSingleObject(handle, ms)
    })
}

pub extern "system" fn WaitForSingleObjectEx(handle: HANDLE, ms: u32, alertable: i32) -> u32 {
    // SAFETY: the title's handle, passed on as it is.
    timed(Api::SingleEx, handle as usize, ms, || unsafe {
        host::WaitForSingleObjectEx(handle, ms, alertable)
    })
}

pub extern "system" fn WaitForMultipleObjects(
    count: u32,
    handles: *const HANDLE,
    all: i32,
    ms: u32,
) -> u32 {
    // SAFETY: the title's handles, passed on as they are.
    timed(Api::Multiple, count as usize, ms, || unsafe {
        host::WaitForMultipleObjects(count, handles, all, ms)
    })
}

#[derive(Default)]
struct Line {
    sum: Sum,
    threads: Vec<u32>,
    /// Waits going on at the report, and the oldest's age.
    going: u32,
    oldest_micros: u64,
}

/// The reporter: every [`WINDOW`], the sites by blocked time.
fn report() {
    let threshold = threshold_ms().unwrap_or(100) * 1000;
    let mut last = now_micros();
    loop {
        std::thread::sleep(WINDOW);
        let now = now_micros();
        let all: Vec<Arc<Slot>> = slots().lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut lines: HashMap<Site, Line> = HashMap::new();
        for slot in &all {
            let done = std::mem::take(&mut *slot.done.lock().unwrap_or_else(|e| e.into_inner()));
            for (site, sum) in done {
                let line = lines.entry(site).or_default();
                line.sum.waits += sum.waits;
                line.sum.micros += sum.micros;
                if sum.longest_micros >= line.sum.longest_micros {
                    (line.sum.longest_micros, line.sum.object, line.sum.timeout) =
                        (sum.longest_micros, sum.object, sum.timeout);
                }
                if !line.threads.contains(&slot.thread) {
                    line.threads.push(slot.thread);
                }
            }
            let since = slot.since.load(Relaxed);
            let Some(api) = Api::of(slot.api.load(Relaxed)).filter(|_| since != 0 && since < now)
            else {
                continue;
            };
            let site = (api, std::array::from_fn(|i| slot.callers[i].load(Relaxed)));
            let line = lines.entry(site).or_default();
            let age = now - since;
            line.going += 1;
            line.sum.micros += age.min(now - last);
            line.oldest_micros = line.oldest_micros.max(age);
            if age >= line.sum.longest_micros {
                (line.sum.longest_micros, line.sum.object, line.sum.timeout) =
                    (age, slot.object.load(Relaxed), slot.timeout.load(Relaxed));
            }
            if !line.threads.contains(&slot.thread) {
                line.threads.push(slot.thread);
            }
        }
        let mut lines: Vec<(Site, Line)> = lines
            .into_iter()
            .filter(|(_, l)| l.sum.micros >= threshold)
            .collect();
        lines.sort_unstable_by_key(|(_, l)| std::cmp::Reverse(l.sum.micros));
        let seconds = (now - last) as f64 / 1e6;
        tracing::warn!(
            "wait log: {:.1} s window ending {:.1} s after the first wait; {} sites blocked {} ms or more, {} threads seen",
            seconds,
            now as f64 / 1e6,
            lines.len(),
            threshold / 1000,
            all.len()
        );
        for ((api, callers), line) in lines.into_iter().take(LINES) {
            let from: Vec<String> = callers
                .iter()
                .filter(|&&c| c != 0)
                .map(|&c| victory_loader::locate(c))
                .collect();
            let timeout = match line.sum.timeout {
                u32::MAX => "no timeout".to_string(),
                ms => format!("{ms} ms timeout"),
            };
            tracing::warn!(
                "wait log: {:.0} ms blocked in {} at {}: {} threads (first {} \"{}\"), {} waits ended, {} going on (oldest {:.1} s); longest {:.1} s on {:#x} with {}",
                line.sum.micros as f64 / 1e3,
                api.name(),
                from.join(" < "),
                line.threads.len(),
                line.threads[0],
                name_of(line.threads[0]),
                line.sum.waits,
                line.going,
                line.oldest_micros as f64 / 1e6,
                line.sum.longest_micros as f64 / 1e6,
                line.sum.object,
                timeout
            );
        }
        last = now;
        LAST_REPORT.store(now, Relaxed);
    }
}

/// A thread's description, if it has one.
fn name_of(thread: u32) -> String {
    // SAFETY: opens a thread of our own process for its description; the
    // system allocates the string and we free it.
    unsafe {
        let handle = host::OpenThread(host::THREAD_QUERY_LIMITED_INFORMATION, 0, thread);
        if handle.is_null() {
            return String::new();
        }
        let mut name = std::ptr::null_mut();
        let ok = host::GetThreadDescription(handle, &mut name) >= 0 && !name.is_null();
        CloseHandle(handle);
        if !ok {
            return String::new();
        }
        let len = (0..).take_while(|&i| *name.add(i) != 0).count();
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(name, len));
        LocalFree(name.cast::<c_void>());
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_is_a_threshold() {
        assert_eq!(asked("1"), Some(100));
        assert_eq!(asked(" 250 "), Some(250));
        assert_eq!(asked("0"), None);
        assert_eq!(asked("on"), None);
    }

    #[test]
    fn a_wait_is_summed_at_its_site() {
        let mut sum = Sum::default();
        sum.add(5, 5, 0x10, 7);
        sum.add(2, 9, 0x20, u32::MAX);
        sum.add(3, 3, 0x30, 1);
        assert_eq!(
            (
                sum.waits,
                sum.micros,
                sum.longest_micros,
                sum.object,
                sum.timeout
            ),
            (3, 10, 9, 0x20, u32::MAX)
        );
    }
}
