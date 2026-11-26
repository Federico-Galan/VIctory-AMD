//! Constant-mask specialization for `v_cmp_class_f32`.

use super::bitcode::{Bin, Module, V, pred};

/// Contiguous `abs(u)` intervals covering IEEE-754 binary32 (`0..=0x7FFF_FFFF`).
const F32_ABS_CLASSES: [(u32, u32, u32); 6] = [
    (1 << 6, 0x0000_0000, 0x0000_0000), // ±0
    (1 << 7, 0x0000_0001, 0x007F_FFFF), // ±Denorm
    (1 << 8, 0x0080_0000, 0x7F7F_FFFF), // ±Normal
    (1 << 9, 0x7F80_0000, 0x7F80_0000), // ±Inf
    (1 << 0, 0x7F80_0001, 0x7FBF_FFFF), // sNaN
    (1 << 1, 0x7FC0_0000, 0x7FFF_FFFF), // qNaN
];

/// Contiguous raw `u32` intervals covering IEEE-754 binary32 (`0..=0xFFFF_FFFF`).
const F32_RAW_CLASSES: [(u32, u32, u32); 12] = [
    (1 << 6, 0x0000_0000, 0x0000_0000), // +0
    (1 << 7, 0x0000_0001, 0x007F_FFFF), // +Denorm
    (1 << 8, 0x0080_0000, 0x7F7F_FFFF), // +Normal
    (1 << 9, 0x7F80_0000, 0x7F80_0000), // +Inf
    (1 << 0, 0x7F80_0001, 0x7FBF_FFFF), // +sNaN
    (1 << 1, 0x7FC0_0000, 0x7FFF_FFFF), // +qNaN
    (1 << 5, 0x8000_0000, 0x8000_0000), // -0
    (1 << 4, 0x8000_0001, 0x807F_FFFF), // -Denorm
    (1 << 3, 0x8080_0000, 0xFF7F_FFFF), // -Normal
    (1 << 2, 0xFF80_0000, 0xFF80_0000), // -Inf
    (1 << 0, 0xFF80_0001, 0xFFBF_FFFF), // -sNaN
    (1 << 1, 0xFFC0_0000, 0xFFFF_FFFF), // -qNaN
];

fn merged_class_intervals(mask: u32, table: &[(u32, u32, u32)]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &(bit, lo, hi) in table {
        if mask & bit == 0 {
            continue;
        }
        if let Some(last) = out.last_mut()
            && last.1.checked_add(1) == Some(lo)
        {
            last.1 = hi;
            continue;
        }
        out.push((lo, hi));
    }
    out
}

/// Tests raw IEEE-754 binary32 bit intervals directly (using `abs(u)` for
/// sign-symmetric masks and raw `u` otherwise) instead of emitting the full
/// 10-class cascade.
pub(super) fn fclass_const(m: &mut Module, c: usize, u: V, mask: u32) -> V {
    let mask = mask & 0x3FF;
    if mask == 0 {
        return m.bool(false);
    }
    if mask == 0x3FF {
        return m.bool(true);
    }
    let sym = ((mask >> 5) & 1 == (mask >> 6) & 1)
        && ((mask >> 4) & 1 == (mask >> 7) & 1)
        && ((mask >> 3) & 1 == (mask >> 8) & 1)
        && ((mask >> 2) & 1 == (mask >> 9) & 1);
    let (x, dom_max, intervals, invert) = if sym {
        let pos = merged_class_intervals(mask, &F32_ABS_CLASSES);
        let neg = merged_class_intervals(!mask & 0x3FF, &F32_ABS_CLASSES);
        let abs_mask = m.i32(0x7FFF_FFFF);
        let abs_u = m.bin(c, Bin::And, u, abs_mask);
        if neg.len() < pos.len() {
            (abs_u, 0x7FFF_FFFFu32, neg, true)
        } else {
            (abs_u, 0x7FFF_FFFFu32, pos, false)
        }
    } else {
        let pos = merged_class_intervals(mask, &F32_RAW_CLASSES);
        let neg = merged_class_intervals(!mask & 0x3FF, &F32_RAW_CLASSES);
        if neg.len() < pos.len() {
            (u, u32::MAX, neg, true)
        } else {
            (u, u32::MAX, pos, false)
        }
    };
    if intervals.len() == 1 && invert {
        let (lo, hi) = intervals[0];
        return if lo == hi {
            let klo = m.i32(lo);
            m.cmp(c, pred::NE, x, klo)
        } else if lo == 0 {
            let khi = m.i32(hi);
            m.cmp(c, pred::IUGT, x, khi)
        } else if hi == dom_max {
            let klo = m.i32(lo);
            m.cmp(c, pred::IULT, x, klo)
        } else {
            let neg_lo = m.i32(lo.wrapping_neg());
            let d = m.bin(c, Bin::Add, x, neg_lo);
            let span = m.i32(hi - lo);
            m.cmp(c, pred::IUGT, d, span)
        };
    }
    let mut acc: Option<V> = None;
    for (lo, hi) in intervals {
        let term = if lo == hi {
            let klo = m.i32(lo);
            m.cmp(c, pred::EQ, x, klo)
        } else if lo == 0 {
            let khi = m.i32(hi);
            m.cmp(c, pred::IULE, x, khi)
        } else if hi == dom_max {
            let klo = m.i32(lo);
            m.cmp(c, pred::IUGE, x, klo)
        } else {
            let neg_lo = m.i32(lo.wrapping_neg());
            let d = m.bin(c, Bin::Add, x, neg_lo);
            let span = m.i32(hi - lo);
            m.cmp(c, pred::IULE, d, span)
        };
        acc = Some(match acc {
            Some(prev) => m.bin(c, Bin::Or, prev, term),
            None => term,
        });
    }
    let r = acc.unwrap();
    if invert {
        let yes = m.bool(true);
        m.bin(c, Bin::Xor, r, yes)
    } else {
        r
    }
}

#[cfg(test)]
mod tests {
    use super::{F32_ABS_CLASSES, F32_RAW_CLASSES, merged_class_intervals};

    fn ref_fclass(u: u32) -> u32 {
        let e = (u >> 23) & 0xFF;
        let m = u & 0x7F_FFFF;
        let neg = (u >> 31) != 0;
        match (e, m != 0) {
            (0xFF, true) => {
                if (m & 0x40_0000) != 0 {
                    1
                } else {
                    0
                }
            }
            (0xFF, false) => {
                if neg {
                    2
                } else {
                    9
                }
            }
            (0, false) => {
                if neg {
                    5
                } else {
                    6
                }
            }
            (0, true) => {
                if neg {
                    4
                } else {
                    7
                }
            }
            _ => {
                if neg {
                    3
                } else {
                    8
                }
            }
        }
    }

    #[test]
    fn fclass_const_intervals_match_all_1024_masks_and_boundaries() {
        let boundary_bits: [u32; 20] = [
            0x0000_0000, 0x0000_0001, 0x007F_FFFF, 0x0080_0000, 0x3F80_0000, 0x7F7F_FFFF,
            0x7F80_0000, 0x7F80_0001, 0x7FBF_FFFF, 0x7FC0_0000, 0x7FFF_FFFF, 0x8000_0000,
            0x8000_0001, 0x807F_FFFF, 0x8080_0000, 0xFF7F_FFFF, 0xFF80_0000, 0xFF80_0001,
            0xFFBF_FFFF, 0xFFFF_FFFF,
        ];
        for mask in 0..1024u32 {
            let sym = ((mask >> 5) & 1 == (mask >> 6) & 1)
                && ((mask >> 4) & 1 == (mask >> 7) & 1)
                && ((mask >> 3) & 1 == (mask >> 8) & 1)
                && ((mask >> 2) & 1 == (mask >> 9) & 1);
            for &u in &boundary_bits {
                let want = ((mask >> ref_fclass(u)) & 1) != 0;
                let got = if mask == 0 {
                    false
                } else if mask == 0x3FF {
                    true
                } else if sym {
                    let pos = merged_class_intervals(mask, &F32_ABS_CLASSES);
                    let neg = merged_class_intervals(!mask & 0x3FF, &F32_ABS_CLASSES);
                    let x = u & 0x7FFF_FFFF;
                    if neg.len() < pos.len() {
                        !neg.iter().any(|&(lo, hi)| x >= lo && x <= hi)
                    } else {
                        pos.iter().any(|&(lo, hi)| x >= lo && x <= hi)
                    }
                } else {
                    let pos = merged_class_intervals(mask, &F32_RAW_CLASSES);
                    let neg = merged_class_intervals(!mask & 0x3FF, &F32_RAW_CLASSES);
                    if neg.len() < pos.len() {
                        !neg.iter().any(|&(lo, hi)| u >= lo && u <= hi)
                    } else {
                        pos.iter().any(|&(lo, hi)| u >= lo && u <= hi)
                    }
                };
                assert_eq!(got, want, "mask={mask:#05x} u={u:#010x}");
            }
        }
    }
}
