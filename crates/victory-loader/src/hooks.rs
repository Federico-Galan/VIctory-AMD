//! Title compatibility hooks.

use anyhow::{Result, bail};
use victory_pe::ImageInfo;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub(crate) unsafe fn apply(base: usize, info: &ImageInfo) -> Result<()> {
    unsafe {
        hook_lookup_routine(base, info)?;
        hook_resource_binding_comparator(base, info)?;
        hook_pipeline_binding(base, info)?;
        hook_compute_pipeline_binding(base, info)?;
        hook_secondary_resource_binding_comparator(base, info)?;
    }
    Ok(())
}

/// Targets RVA 0x00B5A5D0 in the main executable: a lookup routine that faults if
/// [rcx] is null, reading 0x68. Guarding against null prevents the 0xc0000005 crash.
unsafe fn hook_lookup_routine(base: usize, info: &ImageInfo) -> Result<()> {
    const TARGET_RVA: usize = 0x00B5A5D0;
    const PROLOGUE: [u8; 8] = [0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54]; // push r15..r12

    if info.size_of_image as usize <= TARGET_RVA + 8 {
        return Ok(());
    }
    let target = (base + TARGET_RVA) as *mut u8;
    // Check if the code at TARGET_RVA matches the expected prologue
    let current = unsafe { std::slice::from_raw_parts(target, 8) };
    if current != PROLOGUE {
        return Ok(());
    }

    let page = crate::tls::near(base, info.size_of_image as usize)?;
    let detour = page;

    // Construct detour
    // 0: 48 85 C9          ; test rcx, rcx
    // 3: 74 13             ; jz ret_null (to offset 24)
    // 5: 48 83 39 00       ; cmp qword ptr [rcx], 0
    // 9: 74 0D             ; jz ret_null (to offset 24)
    // 11: 41 57            ; push r15
    // 13: 41 56            ; push r14
    // 15: 41 55            ; push r13
    // 17: 41 54            ; push r12
    // 19: E9 [disp32]      ; jmp (target + 8)
    // 24: 31 C0            ; xor eax, eax
    // 26: C3               ; ret

    let jmp_back_dest = (base + TARGET_RVA + 8) as isize;
    let jmp_back_src = (detour as isize) + 24;
    let disp_back = (jmp_back_dest - jmp_back_src) as i32;

    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx, rcx
    code.extend_from_slice(&[0x74, 0x13]);       // jz +0x13 (offset 24)
    code.extend_from_slice(&[0x48, 0x83, 0x39, 0x00]); // cmp qword ptr [rcx], 0
    code.extend_from_slice(&[0x74, 0x0D]);       // jz +0x0d (offset 24)
    code.extend_from_slice(&[0x41, 0x57]);       // push r15
    code.extend_from_slice(&[0x41, 0x56]);       // push r14
    code.extend_from_slice(&[0x41, 0x55]);       // push r13
    code.extend_from_slice(&[0x41, 0x54]);       // push r12
    code.push(0xE9);
    code.extend_from_slice(&disp_back.to_le_bytes()); // jmp target + 8
    code.extend_from_slice(&[0x31, 0xC0]);       // xor eax, eax
    code.push(0xC3);                             // ret

    // Copy detour code into the allocated page
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), detour, code.len());
    }

    let mut old = 0;
    if unsafe { VirtualProtect(detour as _, 4096, PAGE_EXECUTE_READ, &mut old) } == 0 {
        bail!("VirtualProtect(detour) failed: {}", std::io::Error::last_os_error());
    }

    // Now patch target with: jmp detour (5 bytes) + 3 NOPs = 8 bytes
    let disp_to_detour = ((detour as isize) - ((target as isize) + 5)) as i32;
    let mut patch = Vec::with_capacity(8);
    patch.push(0xE9);
    patch.extend_from_slice(&disp_to_detour.to_le_bytes());
    patch.extend_from_slice(&[0x90, 0x90, 0x90]); // NOPs for remaining 3 bytes

    if unsafe { VirtualProtect(target as _, 8, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        bail!("VirtualProtect(target) failed: {}", std::io::Error::last_os_error());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, 8);
        VirtualProtect(target as _, 8, old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), target as _, 8);
    }

    tracing::info!(rva = format_args!("{:#x}", TARGET_RVA), "title null-check hook applied");
    Ok(())
}

/// Targets RVA 0x05392B37 in the main executable: resource binding comparator.
/// If `r8` is null it jumps to `0x5392da3` to mark all slots dirty, but if `rdx` is null
/// it falls through and crashes reading `[rdx + 0x38]`. Checking both `r8` and `rdx`
/// safely routes null transitions to `0x5392da3`.
unsafe fn hook_resource_binding_comparator(base: usize, info: &ImageInfo) -> Result<()> {
    const TARGET_RVA: usize = 0x05392B37;
    const EXPECTED: [u8; 9] = [0x4D, 0x85, 0xC0, 0x0F, 0x84, 0x63, 0x02, 0x00, 0x00]; // test r8, r8; je 0x5392da3

    if info.size_of_image as usize <= TARGET_RVA + EXPECTED.len() {
        return Ok(());
    }
    let target = (base + TARGET_RVA) as *mut u8;
    let current = unsafe { std::slice::from_raw_parts(target, EXPECTED.len()) };
    if current != EXPECTED {
        return Ok(());
    }

    let page = crate::tls::near(base, info.size_of_image as usize)?;
    let detour = page;

    let disp_b40 = (base + 0x05392B40) as isize - ((detour as isize) + 15);
    let disp_da3 = (base + 0x05392DA3) as isize - ((detour as isize) + 20);

    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(&[0x4D, 0x85, 0xC0]); // test r8, r8
    code.extend_from_slice(&[0x74, 0x0A]);       // jz to_da3 (offset 15)
    code.extend_from_slice(&[0x48, 0x85, 0xD2]); // test rdx, rdx
    code.extend_from_slice(&[0x74, 0x05]);       // jz to_da3 (offset 15)
    code.push(0xE9);
    code.extend_from_slice(&(disp_b40 as i32).to_le_bytes()); // jmp 0x5392b40
    code.push(0xE9);
    code.extend_from_slice(&(disp_da3 as i32).to_le_bytes()); // jmp 0x5392da3

    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), detour, code.len());
    }

    let mut old = 0;
    if unsafe { VirtualProtect(detour as _, 4096, PAGE_EXECUTE_READ, &mut old) } == 0 {
        bail!("VirtualProtect(detour) failed: {}", std::io::Error::last_os_error());
    }

    let disp_to_detour = ((detour as isize) - ((target as isize) + 5)) as i32;
    let mut patch = Vec::with_capacity(9);
    patch.push(0xE9);
    patch.extend_from_slice(&disp_to_detour.to_le_bytes());
    patch.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]); // 4 NOPs

    if unsafe { VirtualProtect(target as _, EXPECTED.len(), PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        bail!("VirtualProtect(target) failed: {}", std::io::Error::last_os_error());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, EXPECTED.len());
        VirtualProtect(target as _, EXPECTED.len(), old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), target as _, EXPECTED.len());
    }

    tracing::info!(rva = format_args!("{:#x}", TARGET_RVA), "title resource binding null-check hook applied");
    Ok(())
}

/// Targets RVA 0x00032764 in the main executable: pipeline state update.
/// If `0xb5a5d0` lookup returns null, `rax == 0`. Reading `[rax + 0x38]` causes a crash.
/// If `rax` is null, we clear the bound pipeline and skip the binding call, jumping to `0x32826`.
unsafe fn hook_pipeline_binding(base: usize, info: &ImageInfo) -> Result<()> {
    const TARGET_RVA: usize = 0x00032764;
    const EXPECTED: [u8; 7] = [0x48, 0x89, 0x87, 0xB0, 0x23, 0x01, 0x00]; // mov [rdi + 0x123b0], rax

    if info.size_of_image as usize <= TARGET_RVA + EXPECTED.len() {
        return Ok(());
    }
    let target = (base + TARGET_RVA) as *mut u8;
    let current = unsafe { std::slice::from_raw_parts(target, EXPECTED.len()) };
    if current != EXPECTED {
        return Ok(());
    }

    let page = crate::tls::near(base, info.size_of_image as usize)?;
    let detour = page;

    let disp_76b = (base + 0x0003276B) as isize - ((detour as isize) + 17);
    let disp_826 = (base + 0x00032826) as isize - ((detour as isize) + 31);

    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(&[0x48, 0x89, 0x87, 0xB0, 0x23, 0x01, 0x00]); // mov [rdi + 0x123b0], rax
    code.extend_from_slice(&[0x48, 0x85, 0xC0]);                         // test rax, rax
    code.extend_from_slice(&[0x74, 0x05]);                               // jz is_null (offset 17)
    code.push(0xE9);
    code.extend_from_slice(&(disp_76b as i32).to_le_bytes());            // jmp 0x3276b
    // offset 17:
    code.extend_from_slice(&[0x31, 0xD2]);                               // xor edx, edx
    code.extend_from_slice(&[0x48, 0x89, 0x97, 0x48, 0x21, 0x03, 0x00]); // mov [rdi + 0x32148], rdx
    code.push(0xE9);
    code.extend_from_slice(&(disp_826 as i32).to_le_bytes());            // jmp 0x32826

    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), detour, code.len());
    }

    let mut old = 0;
    if unsafe { VirtualProtect(detour as _, 4096, PAGE_EXECUTE_READ, &mut old) } == 0 {
        bail!("VirtualProtect(detour) failed: {}", std::io::Error::last_os_error());
    }

    let disp_to_detour = ((detour as isize) - ((target as isize) + 5)) as i32;
    let mut patch = Vec::with_capacity(7);
    patch.push(0xE9);
    patch.extend_from_slice(&disp_to_detour.to_le_bytes());
    patch.extend_from_slice(&[0x90, 0x90]); // 2 NOPs

    if unsafe { VirtualProtect(target as _, EXPECTED.len(), PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        bail!("VirtualProtect(target) failed: {}", std::io::Error::last_os_error());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, EXPECTED.len());
        VirtualProtect(target as _, EXPECTED.len(), old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), target as _, EXPECTED.len());
    }

    tracing::info!(rva = format_args!("{:#x}", TARGET_RVA), "title pipeline binding null-check hook applied");
    Ok(())
}

/// Targets RVA 0x00032130 in the main executable: compute/resource binding flush.
/// If `[rcx + 0x12328]` is null (no active compute pipeline), accessing `[rbp + 0x50]`
/// causes a 0xc0000005 crash. Guarding against null and returning early prevents the crash.
unsafe fn hook_compute_pipeline_binding(base: usize, info: &ImageInfo) -> Result<()> {
    const TARGET_RVA: usize = 0x00032130;
    const PROLOGUE: [u8; 8] = [0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54]; // push r15..r12

    if info.size_of_image as usize <= TARGET_RVA + PROLOGUE.len() {
        return Ok(());
    }
    let target = (base + TARGET_RVA) as *mut u8;
    let current = unsafe { std::slice::from_raw_parts(target, PROLOGUE.len()) };
    if current != PROLOGUE {
        return Ok(());
    }

    let page = crate::tls::near(base, info.size_of_image as usize)?;
    let detour = page;

    let disp_back = (base + 0x00032138) as isize - ((detour as isize) + 23);

    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(&[0x48, 0x83, 0xB9, 0x28, 0x23, 0x01, 0x00, 0x00]); // cmp qword ptr [rcx + 0x12328], 0
    code.extend_from_slice(&[0x74, 0x0D]);                                     // jz early_ret (offset 23)
    code.extend_from_slice(&[0x41, 0x57]);                                     // push r15
    code.extend_from_slice(&[0x41, 0x56]);                                     // push r14
    code.extend_from_slice(&[0x41, 0x55]);                                     // push r13
    code.extend_from_slice(&[0x41, 0x54]);                                     // push r12
    code.push(0xE9);
    code.extend_from_slice(&(disp_back as i32).to_le_bytes());                  // jmp 0x32138
    code.push(0xC3);                                                           // ret

    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), detour, code.len());
    }

    let mut old = 0;
    if unsafe { VirtualProtect(detour as _, 4096, PAGE_EXECUTE_READ, &mut old) } == 0 {
        bail!("VirtualProtect(detour) failed: {}", std::io::Error::last_os_error());
    }

    let disp_to_detour = ((detour as isize) - ((target as isize) + 5)) as i32;
    let mut patch = Vec::with_capacity(8);
    patch.push(0xE9);
    patch.extend_from_slice(&disp_to_detour.to_le_bytes());
    patch.extend_from_slice(&[0x90, 0x90, 0x90]); // 3 NOPs

    if unsafe { VirtualProtect(target as _, PROLOGUE.len(), PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        bail!("VirtualProtect(target) failed: {}", std::io::Error::last_os_error());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, PROLOGUE.len());
        VirtualProtect(target as _, PROLOGUE.len(), old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), target as _, PROLOGUE.len());
    }

    tracing::info!(rva = format_args!("{:#x}", TARGET_RVA), "title compute pipeline null-check hook applied");
    Ok(())
}

/// Targets RVA 0x00122AF8 in the main executable: secondary resource binding comparator.
/// If `rax` is null it jumps to `0x122cc2` to mark all slots dirty (`0x700001f0ff`), but if `r14` is null
/// it falls through and crashes reading `[r14 + 0x30]`. Checking both `rax` and `r14`
/// safely routes null transitions to `0x122cc2`.
unsafe fn hook_secondary_resource_binding_comparator(base: usize, info: &ImageInfo) -> Result<()> {
    const TARGET_RVA: usize = 0x00122AF8;
    const EXPECTED: [u8; 9] = [0x48, 0x85, 0xC0, 0x0F, 0x84, 0xC1, 0x01, 0x00, 0x00]; // test rax, rax; je 0x122cc2

    if info.size_of_image as usize <= TARGET_RVA + EXPECTED.len() {
        return Ok(());
    }
    let target = (base + TARGET_RVA) as *mut u8;
    let current = unsafe { std::slice::from_raw_parts(target, EXPECTED.len()) };
    if current != EXPECTED {
        return Ok(());
    }

    let page = crate::tls::near(base, info.size_of_image as usize)?;
    let detour = page;

    let disp_b01 = (base + 0x00122B01) as isize - ((detour as isize) + 15);
    let disp_cc2 = (base + 0x00122CC2) as isize - ((detour as isize) + 20);

    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    code.extend_from_slice(&[0x74, 0x0A]);       // jz to_cc2 (offset 15)
    code.extend_from_slice(&[0x4D, 0x85, 0xF6]); // test r14, r14
    code.extend_from_slice(&[0x74, 0x05]);       // jz to_cc2 (offset 15)
    code.push(0xE9);
    code.extend_from_slice(&(disp_b01 as i32).to_le_bytes()); // jmp 0x122b01
    code.push(0xE9);
    code.extend_from_slice(&(disp_cc2 as i32).to_le_bytes()); // jmp 0x122cc2

    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), detour, code.len());
    }

    let mut old = 0;
    if unsafe { VirtualProtect(detour as _, 4096, PAGE_EXECUTE_READ, &mut old) } == 0 {
        bail!("VirtualProtect(detour) failed: {}", std::io::Error::last_os_error());
    }

    let disp_to_detour = ((detour as isize) - ((target as isize) + 5)) as i32;
    let mut patch = Vec::with_capacity(9);
    patch.push(0xE9);
    patch.extend_from_slice(&disp_to_detour.to_le_bytes());
    patch.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]); // 4 NOPs

    if unsafe { VirtualProtect(target as _, EXPECTED.len(), PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        bail!("VirtualProtect(target) failed: {}", std::io::Error::last_os_error());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, EXPECTED.len());
        VirtualProtect(target as _, EXPECTED.len(), old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), target as _, EXPECTED.len());
    }

    tracing::info!(rva = format_args!("{:#x}", TARGET_RVA), "title secondary resource binding null-check hook applied");
    Ok(())
}
