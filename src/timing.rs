//! Where a command's time goes: named phases summed per command (per request under the daemon).
//!
//! DCP_TIMING=1 prints one line to stderr when the command ends: `timing: total=.. open=.. refresh=.. ...` (ms per
//! phase, phases in first-seen order; nested phases count in both). DCP_TIMING=2 adds the per-rule lines the engine
//! records (`rule.<id>`, `rule.<id>.run`, `rule.<id>.record`). Nothing here changes what a command computes.

use std::cell::RefCell;
use std::time::Instant;

thread_local! {
    static STATE: RefCell<(Instant, Vec<(String, f64)>)> = RefCell::new((Instant::now(), vec![]));
}

/// DCP_TIMING: 0 (off), 1 or 2 (anything else that is set: 1).
pub fn level() -> u32 {
    match std::env::var("DCP_TIMING") {
        Ok(v) if v.is_empty() => 0,
        Ok(v) => v.parse().unwrap_or(1),
        Err(_) => 0,
    }
}

pub fn reset() {
    STATE.with(|s| *s.borrow_mut() = (Instant::now(), vec![]));
}

pub fn add(name: &str, ms: f64) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        match s.1.iter_mut().find(|(n, _)| n == name) {
            Some(e) => e.1 += ms,
            None => s.1.push((name.to_string(), ms)),
        }
    });
}

/// f() timed as the phase `name`.
pub fn phase<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = f();
    add(name, t.elapsed().as_secs_f64() * 1000.0);
    r
}

/// The timing line (None when DCP_TIMING is not set); the per-rule entries only at level 2.
pub fn report() -> Option<String> {
    let lv = level();
    if lv == 0 {
        return None;
    }
    STATE.with(|s| {
        let s = s.borrow();
        let mut parts = vec![format!("total={:.0}", s.0.elapsed().as_secs_f64() * 1000.0)];
        parts.extend(s.1.iter().filter(|(k, _)| lv >= 2 || !(k.starts_with("rule.") || k.starts_with("record."))).map(|(k, v)| format!("{k}={v:.0}")));
        Some(format!("timing: {}", parts.join("  ")))
    })
}
