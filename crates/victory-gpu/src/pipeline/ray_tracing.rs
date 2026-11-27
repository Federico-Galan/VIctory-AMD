//! Ray tracing off (`SCARLETT_RAY_TRACING=0`, or `SCARLETT_RAY_TRACING=0`;
//! off by default, live with `SCARLETT_AB=<s>,SCARLETT_RAY_TRACING_OFF`):
//! the passes that walk the structures (BVH traversal) and that sort rays
//! into bins for them are left out, as the hit resolve and ray activation
//! already are without the structure builder (`make::left_out`). Without
//! the builder the structures hold nothing, so these passes trace no hits.
//! From DexNom/ScarlettPort ab34a8b2 (`pipeline/ray_tracing.rs`), only the
//! traversal and ray-bin classes.

use super::Shader;
use std::sync::OnceLock;
use victory_shader::{Container, FourCC};

/// What a pipeline does for ray tracing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Work {
    Traversal,
    RayBins,
    Other,
}

const AB_NAME: &str = "SCARLETT_RAY_TRACING_OFF";

fn asked_off() -> bool {
    static OFF: OnceLock<bool> = OnceLock::new();
    *OFF.get_or_init(|| {
        let var = std::env::var("SCARLETT_RAY_TRACING").or_else(|_| std::env::var("SCARLETT_RAY_TRACING"));
        let off = var.as_deref().is_ok_and(|v| v.trim() == "0");
        if off {
            tracing::info!("ray tracing off: BVH traversal and ray-bin passes left out");
        }
        off
    })
}

/// Whether the switch could be on in this run (asked, or changed by `SCARLETT_AB`).
pub(super) fn may_skip() -> bool {
    #[cfg(feature = "diagnostics")]
    if crate::ab::bit(AB_NAME).is_some() {
        return true;
    }
    asked_off()
}

/// Whether the passes are left out now.
pub(super) fn off_now() -> bool {
    #[cfg(feature = "diagnostics")]
    if let Some(on) = crate::ab::pick(AB_NAME) {
        return on;
    }
    asked_off()
}

/// Why a pipeline of `shaders` is left out while ray tracing is off.
pub(super) fn omission(shaders: &[std::sync::Arc<Shader>]) -> Option<&'static str> {
    if !may_skip() {
        return None;
    }
    shaders.iter().find_map(|s| match classify(s.stage, &s.container) {
        Work::Traversal => Some("ray tracing off: BVH traversal"),
        Work::RayBins => Some("ray tracing off: ray bin preparation"),
        Work::Other => None,
    })
}

const RAY_BIN_ENTRIES: [&[u8]; 5] = [
    b"CS_ScreenProbes_EvaluateRayRequests_RayBinning_",
    b"CS_RayBudgeting_Cull_RayBinning_",
    b"CS_ScreenProbes_GenerateRayBins_",
    b"CS_GenerateRayBins_",
    b"CS_GenerateRayBinOffsets_",
];

fn classify(stage: &str, container: &[u8]) -> Work {
    let Ok(c) = Container::parse(container) else {
        return Work::Other;
    };
    if stage == "compute"
        && c.part(FourCC::PSV0).is_some_and(|psv| {
            psv.data
                .split(|b| *b == 0)
                .any(|entry| RAY_BIN_ENTRIES.iter().any(|name| entry.starts_with(name)))
        })
    {
        return Work::RayBins;
    }
    let Some(programs) = c
        .part(FourCC::DXIL)
        .and_then(|p| victory_shader::native_programs(p.data).ok())
    else {
        return Work::Other;
    };
    if programs.iter().any(|p| traverses(&p.code)) {
        return Work::Traversal;
    }
    Work::Other
}

fn traverses(code: &[u8]) -> bool {
    // The fast scan excludes programs without either MIMG header. Only the
    // decoder can tell a real instruction from a literal or unreachable data.
    code.chunks_exact(4).any(|bytes| {
        let word = u32::from_le_bytes(bytes.try_into().unwrap());
        word >> 26 == 0x3c && (word >> 18) & 0x7e == 0x66 && word & 1 != 0
    }) && victory_shader::gfx10::decode(code).is_ok_and(|instructions| {
        instructions
            .iter()
            .any(|i| matches!(i.name(), Some("image_bvh_intersect_ray" | "image_bvh64_intersect_ray")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_executed_bvh_opcodes_identify_a_traversal_shader() {
        let run = |words: &[u32]| traverses(&words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>());
        for header in [0xf198_9f07, 0xf19c_9f07] {
            assert!(run(&[header, 0x020d01, 0x05040302, 0x09080706, 0x000c0b0a, 0xbf810000]));
            assert!(!run(&[0xbe98_03ff, header, 0xbf810000])); // scalar literal
            assert!(!run(&[0xbf810000, header])); // unreachable tail
        }
        assert_eq!(classify("compute", b"not a container"), Work::Other);
    }
}
