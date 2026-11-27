//! Save slots (`SCARLETT_SAVE_SLOT=<name>`, off by default): each slot is a
//! whole game under `<data>/<TITLEID>/slots/<name>/storage`; a new name
//! starts fresh, an existing one continues. Unset, the title keeps its
//! usual `<data>/<TITLEID>/storage`.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// The slot named by `SCARLETT_SAVE_SLOT`, validated; `None` when unset or empty.
pub fn slot_from_env() -> Result<Option<String>> {
    let Some(name) = std::env::var("SCARLETT_SAVE_SLOT").ok().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    validate(&name)?;
    Ok(Some(name))
}

/// Names are 1 to 64 of letters, digits, `-`, `_` and `.` (not leading), so
/// they can never hold a path separator or climb out.
pub fn validate(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !ok {
        bail!(
            "invalid save slot name {name:?}: use 1-64 letters, digits, '-', '_' or '.', \
             not starting with '.'"
        );
    }
    Ok(())
}

/// Whether slot `default` still means the pre-slot location: saves made
/// before slots existed live in `<title>/storage` and `<title>/saves`, and
/// are slot `default` until a `slots/default` folder exists. Without this a
/// run with `SCARLETT_SAVE_SLOT=default` starts a fresh profile (the first-boot
/// and legal screens again) beside a profile that already accepted them.
/// `title` is the title's data folder (absolute); nothing is created or moved.
pub fn default_is_pre_slot(title: &Path, slot: Option<&str>) -> bool {
    slot == Some("default")
        && !title.join("slots").join("default").exists()
        && (title.join("storage").exists() || title.join("saves").exists())
}

/// The storage folder of `slot` under a title folder (relative to the
/// title's data folder), without creating anything.
pub fn storage(title: &Path, slot: Option<&str>) -> Result<PathBuf> {
    Ok(match slot {
        None => title.join("storage"),
        Some(slot) => {
            validate(slot)?;
            title.join("slots").join(slot).join("storage")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_reject_separators_and_escapes() {
        let long = "n".repeat(65);
        for bad in ["", "a/b", "a\\b", "..", ".hidden", "a:b", "x y", long.as_str()] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
        for good in ["default", "run-2", "A_b.1"] {
            validate(good).unwrap();
        }
    }

    #[test]
    fn default_slot_reads_the_pre_slot_place_until_it_has_a_folder() {
        let t = std::env::temp_dir().join(format!("scarlett-slot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        assert!(!default_is_pre_slot(&t, Some("default")), "nothing there yet");
        std::fs::create_dir_all(t.join("saves")).unwrap();
        assert!(default_is_pre_slot(&t, Some("default")));
        assert!(!default_is_pre_slot(&t, Some("other")));
        assert!(!default_is_pre_slot(&t, None));
        std::fs::create_dir_all(t.join("slots/default")).unwrap();
        assert!(!default_is_pre_slot(&t, Some("default")));
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn slot_paths() {
        let p = Path::new("t");
        assert_eq!(storage(p, None).unwrap(), p.join("storage"));
        assert_eq!(storage(p, Some("b")).unwrap(), p.join("slots/b/storage"));
        assert!(storage(p, Some("../x")).is_err());
    }
}
