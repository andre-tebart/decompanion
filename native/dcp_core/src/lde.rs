//! An x86-32 instruction length decoder for the rules that read only where instructions start and end (M.match's
//! last instruction, M8.reloc's aligned sites). The opcodes whose length the tables below give with certainty
//! (the integer and x87 instructions compilers of the era emit) are measured here; every other instruction (SSE
//! / MMX forms, far pointers, 16-bit addressing, LOCK, unusual x87 register forms) is decoded by capstone alone,
//! so a result is always capstone's: `lengths_selftest` checks the fast path against capstone on random bytes,
//! and the shadow of the rules on every function of gildegold.

/// The length of the instruction at the start of `b` when the tables know it, else None (capstone decides).
pub fn length(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    let mut opsize16 = false;
    // prefixes: operand size, segments, rep / repne (string instructions); LOCK and address size go to capstone
    loop {
        match *b.get(i)? {
            0x66 => opsize16 = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0xf2 | 0xf3 => {}
            0xf0 | 0x67 => return None,
            _ => break,
        }
        i += 1;
        if i > 4 {
            return None;
        }
    }
    let rep = b[..i].iter().any(|&p| p == 0xf2 || p == 0xf3);
    let op = *b.get(i)?;
    i += 1;
    let imm_v = if opsize16 { 2 } else { 4 };
    // (modrm?, immediate bytes)
    let (modrm, imm): (bool, usize) = match op {
        0x0f => return two_byte(b, i, opsize16, rep),
        0x00..=0x3f => match op & 7 {
            0..=3 => (true, 0),
            4 => (false, 1),
            5 => (false, imm_v),
            _ => match op {
                0x06 | 0x07 | 0x0e | 0x16 | 0x17 | 0x1e | 0x1f | 0x27 | 0x2f | 0x37 | 0x3f => (false, 0),
                _ => return None, // prefixes handled above
            },
        },
        0x40..=0x61 => (false, 0),
        0x63 => (true, 0),
        0x68 => (false, imm_v),
        0x69 => (true, imm_v),
        0x6a => (false, 1),
        0x6b => (true, 1),
        0x6c..=0x6f => (false, 0),
        0x70..=0x7f => (false, 1),
        0x80 | 0x83 => (true, 1),
        0x81 => (true, imm_v),
        0x84..=0x8b => (true, 0),
        0x8c | 0x8e => {
            // segment registers 0 .. 5 exist (and `mov cs, ..` is no instruction): capstone for the rest
            let r = modrm_reg(b, i)?;
            if r > 5 || (op == 0x8e && r == 1) {
                return None;
            }
            (true, 0)
        }
        0x8d => {
            if modrm_mod(b, i)? == 3 {
                return None;
            }
            (true, 0)
        }
        0x8f => {
            if modrm_reg(b, i)? != 0 {
                return None;
            }
            (true, 0)
        }
        0x90..=0x99 | 0x9c..=0x9f => (false, 0), // 9b (wait) may join the x87 instruction after it: capstone
        0xa0..=0xa3 => (false, 4),
        0xa4..=0xa7 | 0xaa..=0xaf => (false, 0),
        0xa8 => (false, 1),
        0xa9 => (false, imm_v),
        0xb0..=0xb7 => (false, 1),
        0xb8..=0xbf => (false, imm_v),
        0xc0 | 0xc1 => (true, 1),
        0xc2 | 0xca => (false, 2),
        0xc3 | 0xc9 | 0xcb | 0xcc | 0xce | 0xcf => (false, 0),
        0xc6 => {
            if modrm_reg(b, i)? != 0 {
                return None;
            }
            (true, 1)
        }
        0xc7 => {
            if modrm_reg(b, i)? != 0 {
                return None;
            }
            (true, imm_v)
        }
        0xc8 => (false, 3),
        0xcd => (false, 1),
        0xd0..=0xd3 => (true, 0),
        0xd4 | 0xd5 => (false, 1),
        0xd7 => (false, 0),
        0xd8..=0xdf => {
            if !x87_known(op, *b.get(i)?) {
                return None;
            }
            (true, 0)
        }
        0xe0..=0xe7 | 0xeb => (false, 1),
        0xe8 | 0xe9 => (false, imm_v),
        0xec..=0xef | 0xf4 | 0xf5 | 0xf8..=0xfd => (false, 0),
        0xf6 => match modrm_reg(b, i)? {
            0 => (true, 1),
            1 => return None,
            _ => (true, 0),
        },
        0xf7 => match modrm_reg(b, i)? {
            0 => (true, imm_v),
            1 => return None,
            _ => (true, 0),
        },
        0xfe => {
            if modrm_reg(b, i)? > 1 {
                return None;
            }
            (true, 0)
        }
        0xff => {
            let r = modrm_reg(b, i)?;
            if r == 7 || ((r == 3 || r == 5) && modrm_mod(b, i)? == 3) {
                return None;
            }
            (true, 0)
        }
        _ => return None, // 62 bound / evex, 82, 9a, c4 / c5 vex, d6, ea, f1
    };
    // a rep prefix on anything but a string instruction changes the meaning (pause, SSE): capstone decides
    if rep && !matches!(op, 0x6c..=0x6f | 0xa4..=0xa7 | 0xaa..=0xaf) {
        return None;
    }
    finish(b, i, modrm, imm)
}

fn two_byte(b: &[u8], mut i: usize, opsize16: bool, rep: bool) -> Option<usize> {
    let op = *b.get(i)?;
    i += 1;
    if rep {
        return None;
    }
    let (modrm, imm) = match op {
        0x80..=0x8f => (false, if opsize16 { 2 } else { 4 }),
        0x90..=0x9f | 0x40..=0x4f | 0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf | 0xa3 | 0xab | 0xb3 | 0xbb | 0xa5 | 0xad
        | 0xb0 | 0xb1 | 0xc0 | 0xc1 | 0xbc | 0xbd => {
            if op >= 0x90 && op <= 0x9f && modrm_reg(b, i)? != 0 {
                return None; // setcc with another reg field: capstone decides
            }
            (true, 0)
        }
        0xa4 | 0xac => (true, 1),
        0xba => {
            if modrm_reg(b, i)? < 4 {
                return None;
            }
            (true, 1)
        }
        0xa0 | 0xa1 | 0xa2 | 0xa8 | 0xa9 | 0x31 | 0x0b | 0x77 | 0xc8..=0xcf => (false, 0),
        _ => return None,
    };
    if opsize16 && op == 0x77 {
        return None;
    }
    finish(b, i, modrm, imm)
}

fn modrm_mod(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).map(|m| m >> 6)
}

fn modrm_reg(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).map(|m| (m >> 3) & 7)
}

/// The ModRM byte, SIB and displacement (32-bit addressing), then the immediate.
fn finish(b: &[u8], mut i: usize, modrm: bool, imm: usize) -> Option<usize> {
    if modrm {
        let m = *b.get(i)?;
        i += 1;
        let (md, rm) = (m >> 6, m & 7);
        if md != 3 {
            if rm == 4 {
                let sib = *b.get(i)?;
                i += 1;
                if md == 0 && sib & 7 == 5 {
                    i += 4;
                }
            } else if md == 0 && rm == 5 {
                i += 4;
            }
            i += match md {
                1 => 1,
                2 => 4,
                _ => 0,
            };
        }
    }
    i += imm;
    if i > b.len() || i > 15 {
        return None;
    }
    Some(i)
}

/// The x87 forms the tables trust: every memory form but the reserved ones, the register forms compilers emit.
fn x87_known(op: u8, m: u8) -> bool {
    let (md, reg) = (m >> 6, (m >> 3) & 7);
    if md != 3 {
        return !matches!((op, reg), (0xd9, 1) | (0xdb, 4) | (0xdb, 6) | (0xdd, 5) | (0xdf, 1));
    }
    match op {
        0xd8 => true,
        0xdc => matches!(m, 0xc0..=0xcf | 0xe0..=0xff),
        0xd9 => matches!(m, 0xc0..=0xcf | 0xd0 | 0xe0 | 0xe1 | 0xe4 | 0xe5 | 0xe8..=0xee | 0xf0..=0xff),
        0xda => m == 0xe9 || (0xc0..=0xdf).contains(&m),
        0xdb => matches!(m, 0xc0..=0xdf | 0xe2 | 0xe3 | 0xe8..=0xf7),
        0xdd => matches!(m, 0xc0..=0xc7 | 0xd0..=0xef),
        0xde => matches!(m, 0xc0..=0xcf | 0xd9 | 0xe0..=0xff),
        0xdf => matches!(m, 0xe0 | 0xe8..=0xf7),
        _ => false,
    }
}

/// (address, size) of every instruction from the start of `code` to its end or the first that does not decode,
/// as capstone's disasm gives them: the tables where they know the length, capstone for one instruction where not.
pub fn lengths(dll: &str, code: &[u8], va: u32) -> Result<Vec<(u32, u32)>, String> {
    let mut out = Vec::new();
    let mut o = 0usize;
    while o < code.len() {
        let n = match length(&code[o..]) {
            Some(n) => n,
            None => match crate::cs::one(dll, &code[o..], va.wrapping_add(o as u32))? {
                Some(n) => n,
                None => break,
            },
        };
        out.push((va.wrapping_add(o as u32), n as u32));
        o += n;
    }
    Ok(out)
}
