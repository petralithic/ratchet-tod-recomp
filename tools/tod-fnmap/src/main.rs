//! tod-fnmap: per-version function signatures and address maps for the game's PPU executable.
//!
//! The port names the game's functions by their address in one release (BCES00052 1.00). Another
//! release (BCUS98127) has the same code at other addresses. This tool finds the correspondence
//! without putting any game code in its output:
//!
//!   tod-fnmap sig   <EBOOT.ELF>                       > <release>.fnsig.tsv
//!       One line per function: start address, length in instructions and a 64-bit hash of its
//!       instructions with branch targets, TOC offsets and address halves masked (the same
//!       normalisation as RACiT's update-1.20 function diff), so a function that only moved
//!       hashes the same. Functions are the OPD entries plus every direct `bl` target.
//!
//!   tod-fnmap map   <A.fnsig.tsv> <B.fnsig.tsv> [addrs.txt]
//!       Aligns the two lists (Myers diff on the hashes, changed runs paired in order) and prints
//!       a summary on stderr and the A -> B map on stdout. With addrs.txt (hex addresses of A, one
//!       per line), prints only those, each with how it was matched.
//!
//!   tod-fnmap probe <B EBOOT.ELF> <addrs.txt> [--window 0x400]
//!       Without A's signatures: for each A address, the B function starts within the window form
//!       a set of candidate deltas; a Viterbi pass picks the sequence of deltas that changes least
//!       often along the sorted addresses. A delta shared by a run of neighbours is a strong hint,
//!       a lone one is a guess. Output: A, B guess, delta, run length, candidate count.
//!
//! Signature files hold hashes and addresses only, so a maintainer who owns one release can
//! publish its signature file and anyone with another release can map onto it.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::process::exit;

// ---------------------------------------------------------------------------------------------
// ELF64 big-endian (PS3 PPU executable)
// ---------------------------------------------------------------------------------------------

struct Seg {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    exec: bool,
}

struct Elf {
    data: Vec<u8>,
    segs: Vec<Seg>,
    entry: u64,
    sections: Vec<(String, u64, u64, u64)>, // name, addr, size, flags
}

fn be16(d: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([d[o], d[o + 1]])
}
fn be32(d: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(d[o..o + 4].try_into().unwrap())
}
fn be64(d: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(d[o..o + 8].try_into().unwrap())
}

impl Elf {
    fn load(path: &str) -> Result<Elf, String> {
        let data = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        if data.len() < 0x40 || &data[..4] != b"\x7fELF" || data[4] != 2 || data[5] != 2 {
            return Err(format!("{path}: not a big-endian ELF64 (decrypt the EBOOT.BIN first)"));
        }
        let entry = be64(&data, 0x18);
        let phoff = be64(&data, 0x20) as usize;
        let shoff = be64(&data, 0x28) as usize;
        let phentsize = be16(&data, 0x36) as usize;
        let phnum = be16(&data, 0x38) as usize;
        let shentsize = be16(&data, 0x3A) as usize;
        let shnum = be16(&data, 0x3C) as usize;
        let shstrndx = be16(&data, 0x3E) as usize;
        let mut segs = Vec::new();
        for i in 0..phnum {
            let o = phoff + i * phentsize;
            if be32(&data, o) == 1 {
                segs.push(Seg {
                    vaddr: be64(&data, o + 0x10),
                    offset: be64(&data, o + 0x08),
                    filesz: be64(&data, o + 0x20),
                    exec: be32(&data, o + 4) & 1 != 0,
                });
            }
        }
        let mut sections = Vec::new();
        if shoff != 0 && shnum != 0 && shoff + shnum * shentsize <= data.len() {
            let stro = be64(&data, shoff + shstrndx * shentsize + 0x18) as usize;
            for i in 0..shnum {
                let o = shoff + i * shentsize;
                let name_off = stro + be32(&data, o) as usize;
                let end = data[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
                let name = String::from_utf8_lossy(&data[name_off..name_off + end]).into_owned();
                sections.push((name, be64(&data, o + 0x10), be64(&data, o + 0x20), be64(&data, o + 0x08)));
            }
        }
        Ok(Elf { data, segs, entry, sections })
    }

    fn word(&self, a: u64) -> Option<u32> {
        for s in &self.segs {
            if a >= s.vaddr && a + 4 <= s.vaddr + s.filesz {
                return Some(be32(&self.data, (s.offset + a - s.vaddr) as usize));
            }
        }
        None
    }

    /// Executable sections (SHF_EXECINSTR), or the executable segment without section headers.
    fn code_ranges(&self) -> Vec<(u64, u64)> {
        let mut r: Vec<(u64, u64)> = self
            .sections
            .iter()
            .filter(|s| s.3 & 4 != 0 && s.2 != 0)
            .map(|s| (s.1, s.1 + s.2))
            .collect();
        if r.is_empty() {
            r = self.segs.iter().filter(|s| s.exec).map(|s| (s.vaddr, s.vaddr + s.filesz)).collect();
        }
        r.sort();
        r
    }

    /// Function entry points: the OPD (the section holding the entry descriptor) plus every
    /// direct `bl` target inside the code.
    fn function_starts(&self) -> Vec<u64> {
        let code = self.code_ranges();
        let in_code = |a: u64| code.iter().any(|&(lo, hi)| a >= lo && a < hi);
        let mut starts = BTreeSet::new();
        if let Some(opd) = self
            .sections
            .iter()
            .find(|s| self.entry >= s.1 && self.entry < s.1 + s.2)
        {
            let mut a = opd.1;
            while a + 8 <= opd.1 + opd.2 {
                if let Some(f) = self.word(a) {
                    if in_code(f as u64) && f % 4 == 0 {
                        starts.insert(f as u64);
                    }
                }
                a += 8;
            }
        }
        for &(lo, hi) in &code {
            let mut a = lo;
            while a < hi {
                if let Some(w) = self.word(a) {
                    // bl (opcode 18, AA=0, LK=1)
                    if w >> 26 == 18 && w & 3 == 1 {
                        let mut off = (w & 0x03FF_FFFC) as i64;
                        if off & 0x0200_0000 != 0 {
                            off -= 0x0400_0000;
                        }
                        let t = (a as i64 + off) as u64;
                        if in_code(t) {
                            starts.insert(t);
                        }
                    }
                }
                a += 4;
            }
        }
        starts.into_iter().collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Normalisation (as RACiT tools/racit_update120_fndiff.py: branch targets, TOC and lis-based
// displacements masked) and hashing
// ---------------------------------------------------------------------------------------------

fn normalise(words: &[u32]) -> Vec<u32> {
    let mut lis = [false; 32];
    let mut out = Vec::with_capacity(words.len());
    for &w0 in words {
        let mut w = w0;
        let op = w >> 26;
        if op == 18 {
            w &= !0x03FF_FFFC;
        } else if op == 16 {
            w &= !0x0000_FFFC;
        } else {
            let rd = ((w >> 21) & 31) as usize;
            let ra = ((w >> 16) & 31) as usize;
            const DISP: [u32; 18] = [14, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 58, 62, 24, 12, 13];
            if op == 15 && ra == 0 {
                lis[rd] = true;
                w &= 0xFFFF_0000;
            } else if DISP.contains(&op) && (ra == 2 || lis[ra]) {
                w &= if op != 58 && op != 62 { 0xFFFF_0000 } else { 0xFFFF_0003 };
                if op == 14 && lis[ra] {
                    lis[rd] = true;
                }
            } else if op == 15 && ra == 2 {
                w &= 0xFFFF_0000;
            }
            if op != 15 && op != 14 && lis[rd] && ![36, 38, 44, 37, 39, 45, 62].contains(&op) {
                lis[rd] = false;
            }
        }
        out.push(w);
    }
    out
}

fn fnv1a64(words: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for w in words {
        for b in w.to_be_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

struct Sig {
    start: u64,
    len: u32,
    hash: u64,
}

fn signatures(elf: &Elf) -> Vec<Sig> {
    let code = elf.code_ranges();
    let starts = elf.function_starts();
    let mut out = Vec::with_capacity(starts.len());
    for (i, &s) in starts.iter().enumerate() {
        let range_end = code.iter().find(|&&(lo, hi)| s >= lo && s < hi).map(|r| r.1).unwrap_or(s);
        let next = starts.get(i + 1).copied().unwrap_or(range_end).min(range_end);
        let mut words = Vec::new();
        let mut a = s;
        while a < next {
            match elf.word(a) {
                Some(w) => words.push(w),
                None => break,
            }
            a += 4;
        }
        let n = normalise(&words);
        out.push(Sig { start: s, len: n.len() as u32, hash: fnv1a64(&n) });
    }
    out
}

fn read_sig(path: &str) -> Result<Vec<Sig>, String> {
    let txt = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut v = Vec::new();
    for line in txt.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 3 {
            return Err(format!("{path}: bad line: {line}"));
        }
        let p = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16);
        v.push(Sig {
            start: p(f[0]).map_err(|e| format!("{path}: {e}"))?,
            len: f[1].parse().map_err(|e| format!("{path}: {e}"))?,
            hash: p(f[2]).map_err(|e| format!("{path}: {e}"))?,
        });
    }
    Ok(v)
}

fn read_addrs(path: &str) -> Result<Vec<u64>, String> {
    let txt = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut v: Vec<u64> = txt
        .split_whitespace()
        .filter_map(|s| u64::from_str_radix(s.trim_start_matches("func_").trim_start_matches("0x"), 16).ok())
        .collect();
    v.sort();
    v.dedup();
    Ok(v)
}

// ---------------------------------------------------------------------------------------------
// Myers diff (O((N+M)D)) on the hash sequences -> list of equal runs
// ---------------------------------------------------------------------------------------------

/// Returns (a_index, b_index) pairs of equal elements along one shortest edit script.
fn myers(a: &[u64], b: &[u64]) -> Vec<(usize, usize)> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    let max = (n + m) as usize;
    let off = max as isize;
    let mut v = vec![0isize; 2 * max + 2];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = false;
    for d in 0..=max as isize {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && v[(off + k - 1) as usize] < v[(off + k + 1) as usize]) {
                v[(off + k + 1) as usize]
            } else {
                v[(off + k - 1) as usize] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[(off + k) as usize] = x;
            if x >= n && y >= m {
                found = true;
                break;
            }
            k += 2;
        }
        if found {
            break;
        }
    }
    // Backtrack.
    let mut pairs = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..trace.len() as isize).rev() {
        let v = &trace[d as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && v[(off + k - 1) as usize] < v[(off + k + 1) as usize]) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = if d == 0 { 0 } else { v[(off + prev_k) as usize] };
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y && x > 0 && y > 0 {
            x -= 1;
            y -= 1;
            pairs.push((x as usize, y as usize));
        }
        if d > 0 {
            x = prev_x;
            y = prev_y;
        }
    }
    pairs.reverse();
    pairs
}

// ---------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------

fn cmd_sig(elf_path: &str) -> Result<(), String> {
    let elf = Elf::load(elf_path)?;
    let sigs = signatures(&elf);
    let code = elf.code_ranges();
    let mut o = io::BufWriter::new(io::stdout().lock());
    let _ = writeln!(o, "# tod-fnmap sig v1: start\tinsns\tfnv1a64(normalised insns); {} functions", sigs.len());
    for (lo, hi) in &code {
        let _ = writeln!(o, "# code {lo:#010x}..{hi:#010x}");
    }
    for s in &sigs {
        let _ = writeln!(o, "{:08X}\t{}\t{:016x}", s.start, s.len, s.hash);
    }
    eprintln!("{} functions", sigs.len());
    Ok(())
}

fn cmd_map(a_path: &str, b_path: &str, addrs: Option<&str>) -> Result<(), String> {
    let a = read_sig(a_path)?;
    let b = read_sig(b_path)?;
    let ah: Vec<u64> = a.iter().map(|s| s.hash).collect();
    let bh: Vec<u64> = b.iter().map(|s| s.hash).collect();
    let eq = myers(&ah, &bh);
    // A index -> (B index, how)
    let mut map: HashMap<usize, (usize, &'static str)> = HashMap::new();
    for &(i, j) in &eq {
        map.insert(i, (j, "same"));
    }
    // Pair the changed runs between equal anchors, in order.
    let mut changed = 0usize;
    let mut only_a = 0usize;
    let mut only_b = 0usize;
    let mut anchors = vec![(usize::MAX, usize::MAX)];
    anchors.extend(eq.iter().copied());
    anchors.push((a.len(), b.len()));
    for w in anchors.windows(2) {
        let (pa, pb) = w[0];
        let (na, nb) = w[1];
        let sa = if pa == usize::MAX { 0 } else { pa + 1 };
        let sb = if pb == usize::MAX { 0 } else { pb + 1 };
        let la = na - sa;
        let lb = nb - sb;
        let k = la.min(lb);
        for t in 0..k {
            map.insert(sa + t, (sb + t, "changed"));
        }
        changed += k;
        only_a += la - k;
        only_b += lb - k;
    }
    eprintln!(
        "A {} functions, B {}: identical {}, changed {}, only in A {}, only in B {}",
        a.len(),
        b.len(),
        eq.len(),
        changed,
        only_a,
        only_b
    );
    let mut o = io::BufWriter::new(io::stdout().lock());
    match addrs {
        None => {
            let _ = writeln!(o, "A\tB\tmatch\tA_insns\tB_insns");
            for (i, s) in a.iter().enumerate() {
                match map.get(&i) {
                    Some(&(j, how)) => {
                        let _ = writeln!(o, "{:08X}\t{:08X}\t{how}\t{}\t{}", s.start, b[j].start, s.len, b[j].len);
                    }
                    None => {
                        let _ = writeln!(o, "{:08X}\t-\tonly_A\t{}\t", s.start, s.len);
                    }
                }
            }
        }
        Some(p) => {
            let idx: HashMap<u64, usize> = a.iter().enumerate().map(|(i, s)| (s.start, i)).collect();
            let _ = writeln!(o, "A\tB\tmatch");
            for x in read_addrs(p)? {
                match idx.get(&x).and_then(|i| map.get(i)) {
                    Some(&(j, how)) => {
                        let _ = writeln!(o, "{x:08X}\t{:08X}\t{how}", b[j].start);
                    }
                    None if idx.contains_key(&x) => {
                        let _ = writeln!(o, "{x:08X}\t-\tonly_A");
                    }
                    None => {
                        let _ = writeln!(o, "{x:08X}\t-\tnot_a_function_start_in_A");
                    }
                }
            }
        }
    }
    Ok(())
}

fn cmd_probe(elf_path: &str, addrs_path: &str, window: i64, only: Option<Vec<i64>>) -> Result<(), String> {
    let elf = Elf::load(elf_path)?;
    let starts: BTreeSet<u64> = elf.function_starts().into_iter().collect();
    let code = elf.code_ranges();
    let (lo, hi) = (code.first().map(|r| r.0).unwrap_or(0), code.last().map(|r| r.1).unwrap_or(0));
    let addrs: Vec<u64> = read_addrs(addrs_path)?.into_iter().filter(|&a| a >= lo && a < hi).collect();
    // Candidate deltas per address (restricted to `only` when given: a step-function model).
    let cands: Vec<Vec<i64>> = addrs
        .iter()
        .map(|&a| {
            starts
                .range((a as i64 - window).max(0) as u64..=(a as i64 + window) as u64)
                .map(|&s| s as i64 - a as i64)
                .filter(|d| only.as_ref().map_or(true, |o| o.contains(d)))
                .collect()
        })
        .collect();
    // Viterbi: state = chosen delta (or "none"); cost 1 per change of delta, 3 for "none".
    const CHANGE: u32 = 1;
    const NONE: u32 = 3;
    let n = addrs.len();
    let mut cost: Vec<Vec<u32>> = Vec::with_capacity(n);
    let mut back: Vec<Vec<usize>> = Vec::with_capacity(n);
    for i in 0..n {
        let states = cands[i].len() + 1; // last = none
        let mut c = vec![u32::MAX; states];
        let mut bk = vec![0usize; states];
        for s in 0..states {
            let own = if s == states - 1 { NONE } else { 0 };
            if i == 0 {
                c[s] = own;
                continue;
            }
            let prev = &cost[i - 1];
            let pstates = prev.len();
            for p in 0..pstates {
                let same = s < states - 1 && p < pstates - 1 && cands[i - 1][p] == cands[i][s];
                let t = prev[p].saturating_add(own).saturating_add(if same { 0 } else { CHANGE });
                if t < c[s] {
                    c[s] = t;
                    bk[s] = p;
                }
            }
        }
        cost.push(c);
        back.push(bk);
    }
    let mut choice = vec![usize::MAX; n];
    if n > 0 {
        let last = &cost[n - 1];
        let mut s = (0..last.len()).min_by_key(|&s| last[s]).unwrap();
        for i in (0..n).rev() {
            choice[i] = s;
            s = back[i][s];
        }
    }
    let delta_of = |i: usize| -> Option<i64> {
        let s = choice[i];
        if s < cands[i].len() {
            Some(cands[i][s])
        } else {
            None
        }
    };
    // Run lengths of equal deltas.
    let mut run = vec![1usize; n];
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && delta_of(j).is_some() && delta_of(j) == delta_of(i) {
            j += 1;
        }
        for k in i..j {
            run[k] = j - i;
        }
        i = j;
    }
    let mut o = io::BufWriter::new(io::stdout().lock());
    let _ = writeln!(o, "A\tB_guess\tdelta\trun\tcandidates\texact_start_in_B");
    let mut strong = 0;
    for i in 0..n {
        let a = addrs[i];
        match delta_of(i) {
            Some(d) => {
                if run[i] >= 3 {
                    strong += 1;
                }
                let _ = writeln!(
                    o,
                    "{a:08X}\t{:08X}\t{d:+#x}\t{}\t{}\t{}",
                    (a as i64 + d) as u64,
                    run[i],
                    cands[i].len(),
                    starts.contains(&a) as u8
                );
            }
            None => {
                let _ = writeln!(o, "{a:08X}\t-\t-\t0\t{}\t{}", cands[i].len(), starts.contains(&a) as u8);
            }
        }
    }
    eprintln!(
        "{} B function starts; {} A addresses in code; {} in runs of >= 3 equal deltas (strong), {} weak",
        starts.len(),
        n,
        strong,
        n - strong
    );
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  tod-fnmap sig <EBOOT.ELF>\n  tod-fnmap map <A.fnsig.tsv> <B.fnsig.tsv> [addrs.txt]\n  tod-fnmap probe <B EBOOT.ELF> <addrs.txt> [--window 0x400] [--deltas 0,0x30,...]"
    );
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("sig") if args.len() == 3 => cmd_sig(&args[2]),
        Some("map") if args.len() == 4 || args.len() == 5 => cmd_map(&args[2], &args[3], args.get(4).map(String::as_str)),
        Some("probe") if args.len() >= 4 => {
            let hex = |s: &str| -> i64 {
                let (neg, s) = s.strip_prefix('-').map_or((false, s), |r| (true, r));
                let v = i64::from_str_radix(s.trim_start_matches("+").trim_start_matches("0x"), 16).unwrap_or_else(|_| usage());
                if neg { -v } else { v }
            };
            let mut w = 0x400;
            let mut only = None;
            let mut i = 4;
            while i < args.len() {
                match (args[i].as_str(), args.get(i + 1)) {
                    ("--window", Some(v)) => w = hex(v),
                    ("--deltas", Some(v)) => only = Some(v.split(',').map(|s| hex(s)).collect()),
                    _ => usage(),
                }
                i += 2;
            }
            cmd_probe(&args[2], &args[3], w, only)
        }
        _ => usage(),
    };
    if let Err(e) = r {
        eprintln!("tod-fnmap: {e}");
        exit(1);
    }
}
