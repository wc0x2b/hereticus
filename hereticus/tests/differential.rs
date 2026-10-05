//! Check the decoder against `llvm-objdump` on every fixture function.
//!
//! Hand-written byte tests only cover encodings someone thought to write. This
//! harness covers everything the compiler emits, which is where a decoder
//! actually fails.
//!
//! The first comparison is on instruction **boundaries and mnemonics**. A
//! disagreement on boundaries means the decoder lost sync, and every
//! instruction after it is wrong. The second compares the operands too,
//! after folding the spellings the two tools differ in, and locks how many
//! still differ.

use std::path::{Path, PathBuf};
use std::process::Command;

use hereticus::arch::{InsnKind, decode_all};
use hereticus::obj::{Binary, Isa};

/// One instruction as `llvm-objdump` reported it.
#[derive(Debug, PartialEq, Eq)]
struct ObjdumpInsn {
    address: u64,
    mnemonic: String,
}

/// Reduce a mnemonic to a form both disassemblers agree on.
///
/// The two tools decode the same bits but print them differently. Each rule
/// below was confirmed against the encoding, not assumed:
///
/// * `cmp` always sets flags, so `yaxpeax` writes the `s` suffix that LLVM
///   leaves implied.
/// * `movw` is the wide immediate move, which `yaxpeax` prints as `mov`.
/// * `lsr` is an alias of `mov` with a shifted operand; LLVM prefers the
///   alias.
/// * `rrx` is an alias of `mov` with a rotate-right-extended operand.
/// * `adr` is `add <reg>, pc, #imm`, which LLVM prints in the long form.
/// * LLVM folds the condition code into the mnemonic (`movlo`), while
///   `yaxpeax` keeps it separate. Strip a trailing condition before
///   comparing.
///
/// Keep this list short and justified. Each entry hides a real difference, so
/// a wrong entry hides a real bug.
fn canonical_mnemonic(mnemonic: &str) -> String {
    // Fold spellings before stripping, because `movs` ends in `vs`, which is
    // also the overflow-set condition. Fold again after, because a condition
    // can wrap an alias, as in `movwlt`.
    fold_alias(strip_condition(fold_alias(mnemonic))).to_string()
}

/// Reduce a MIPS mnemonic to a form both disassemblers agree on.
///
/// Kept apart from [`canonical_mnemonic`] because the ARM rules actively
/// damage MIPS names: `beq` ends in the equal condition, so ARM's stripping
/// would reduce both `beq` and `bne` to `b` and hide a decoder that confused
/// the two.
///
/// * `move` is `or <reg>, <reg>, zero`, which LLVM prints as the alias and
///   `yaxpeax` also prefers; both agree, so only the `addu`/`add` pair below
///   needs folding.
/// * `b` is `beq` of a register with itself. `yaxpeax` prints the alias,
///   LLVM prints the underlying branch.
/// * `nop` is `sll zero, zero, 0`, and `move` is `or <reg>, <reg>, zero`.
///   Each tool prefers a different one of the two spellings.
/// * `beqz` and `bnez` compare against `zero`, which LLVM folds into the
///   mnemonic and `yaxpeax` leaves as an operand. The pair stays distinct:
///   `beqz` folds to `beq` and `bnez` to `bne`, so a decoder that confused
///   the two would still fail.
///
/// Every entry here hides a real difference, so each is confirmed against the
/// encoding rather than added to make the test pass.
fn canonical_mips_mnemonic(mnemonic: &str) -> String {
    match mnemonic {
        "b" | "beqz" => "beq",
        "bnez" => "bne",
        "nop" => "sll",
        "move" => "or",
        other => other,
    }
    .to_string()
}

/// Map the spellings that mean the same encoding onto one name.
fn fold_alias(mnemonic: &str) -> &str {
    match mnemonic {
        "cmps" => "cmp",
        "adr" => "add",
        "movw" | "movs" | "lsr" | "lsrs" | "rrx" => "mov",
        other => other,
    }
}

/// Remove a trailing ARM condition code.
///
/// Only strip when the stem is still a plausible mnemonic. Several mnemonics
/// end in the same letters as a condition (`movs` in `vs`, `ble` in `le`), and
/// stripping those would produce nonsense.
fn strip_condition(mnemonic: &str) -> &str {
    const CONDITIONS: [&str; 17] = [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        // `lo` and `hs` are the other spellings of `cc` and `cs`.
        "lo", "hs",
    ];

    // Mnemonics that end in condition letters but carry no condition.
    const NOT_CONDITIONAL: [&str; 6] = ["b", "bl", "ble", "bls", "movs", "cmps"];

    if NOT_CONDITIONAL.contains(&mnemonic) {
        return mnemonic;
    }

    for suffix in &CONDITIONS {
        if let Some(stem) = mnemonic.strip_suffix(suffix)
            // A real mnemonic is at least two characters, so `bx` survives
            // but a one-letter stem means the match was a coincidence.
            && stem.len() >= 2
        {
            return stem;
        }
    }
    mnemonic
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

/// Fixture objects that keep their symbols, or an empty list when
/// `just fixtures` has not run.
///
/// Stripped fixtures are skipped. This harness asks `llvm-objdump` to
/// disassemble one symbol at a time, which needs a name, and a recovered
/// function has none. Recovery is measured in `tests/stripped.rs` instead.
fn fixture_objects() -> Vec<PathBuf> {
    let mut objects = Vec::new();
    let Ok(levels) = std::fs::read_dir(fixtures_dir()) else { return objects };

    for level in levels.flatten() {
        let name = level.file_name();
        let name = name.to_string_lossy();
        if name.ends_with("-stripped") || name == "bare" {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(level.path()) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "o") {
                objects.push(path);
            }
        }
    }
    objects.sort();
    objects
}

/// Disassemble one symbol with `llvm-objdump`.
///
/// Returns `None` when `llvm-objdump` is missing, so the test can skip instead
/// of failing on a machine without it.
fn objdump_function(object: &Path, triple: &str, symbol: &str) -> Option<Vec<ObjdumpInsn>> {
    let output = Command::new("llvm-objdump")
        .arg("-d")
        .arg(format!("--triple={triple}"))
        .arg(format!("--disassemble-symbols={symbol}"))
        .arg(object)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    Some(parse_objdump(&String::from_utf8_lossy(&output.stdout)))
}

/// Pull address and mnemonic out of `llvm-objdump` text.
///
/// Instruction lines look like:
/// ```text
///        0: e0810000     <TAB>add<TAB>r0, r1, r0
/// ```
///
/// The separators are real tab characters, written here as `<TAB>` so the
/// example stays readable.
fn parse_objdump(text: &str) -> Vec<ObjdumpInsn> {
    let mut out = Vec::new();

    for line in text.lines() {
        let Some((address_part, rest)) = line.split_once(':') else { continue };
        let Ok(address) = u64::from_str_radix(address_part.trim(), 16) else { continue };

        // After the colon comes the encoding, then a tab, then the mnemonic.
        let mut fields = rest.split('\t').map(str::trim).filter(|field| !field.is_empty());
        let Some(_encoding) = fields.next() else { continue };
        let Some(mnemonic) = fields.next() else { continue };

        // Data that objdump cannot decode prints as `<unknown>`; skip it.
        if mnemonic.starts_with('<') {
            continue;
        }

        // An instruction with no operands, such as the MIPS `nop`, has
        // nothing between the mnemonic and the symbol annotation objdump
        // appends, so `nop <add>` arrives as one field. Keep the first word.
        let mnemonic = mnemonic.split_whitespace().next().unwrap_or(mnemonic);

        out.push(ObjdumpInsn { address, mnemonic: mnemonic.to_string() });
    }

    out
}

#[test]
fn decoder_agrees_with_objdump() {
    let objects = fixture_objects();
    assert!(
        !objects.is_empty(),
        "no fixtures found in {}; run `just fixtures` first",
        fixtures_dir().display()
    );

    let mut checked_functions = 0usize;
    let mut checked_instructions = 0usize;
    let mut unknown_instructions = 0usize;
    let mut skipped_objects = 0usize;

    for object_path in &objects {
        let data = std::fs::read(object_path).expect("fixture must be readable");
        let binary = Binary::parse(&data).expect("fixture must parse");
        let arch = binary.isa.arch();

        for function in &binary.functions {
            let Some(expected) = objdump_function(object_path, arch.triple(), &function.name)
            else {
                skipped_objects += 1;
                continue;
            };
            if expected.is_empty() {
                continue;
            }

            // The two tools disagree about where a function ends, in both
            // directions, and neither disagreement is a decoder fault:
            //
            // * A symbol can cover data as well as code. Jump tables and
            //   constant pools sit inside `.text` within the function extent,
            //   so this decoder reads words that `llvm-objdump` skips.
            // * `llvm-objdump` disassembles to the next symbol, not to the
            //   end of this one, so it can print alignment padding that the
            //   symbol size excludes.
            //
            // Compare the overlap, which is the part both call code. Deciding
            // where a function truly ends belongs to function recovery.
            let (decoded, _error) = decode_all(arch, &function.code, function.address);
            let where_ = format!("{}: {}", object_path.display(), function.name);
            let shared = decoded.len().min(expected.len());
            assert!(shared > 0, "{where_}: nothing to compare");

            // Each architecture folds spellings its own way. Using ARM's
            // rules on MIPS would strip real mnemonics down to nothing.
            let canonical: fn(&str) -> String = match binary.isa {
                Isa::Arm32 | Isa::Thumb2 | Isa::Aarch64 => canonical_mnemonic,
                Isa::Mips32 | Isa::Mips32Be | Isa::Mips16 | Isa::Mips16Be => {
                    canonical_mips_mnemonic
                }
            };

            for (ours, theirs) in decoded.iter().zip(&expected).take(shared) {
                assert_eq!(
                    ours.address, theirs.address,
                    "{where_}: address differs at {:#x}",
                    theirs.address
                );
                // `llvm-objdump` decodes NEON, this decoder does not. Those
                // words come back opaque, and their width is already checked
                // by the address comparison above.
                if ours.kind == InsnKind::Unknown {
                    unknown_instructions += 1;
                    continue;
                }

                assert_eq!(
                    canonical(&ours.mnemonic),
                    canonical(&theirs.mnemonic),
                    "{where_}: mnemonic differs at {:#x}",
                    theirs.address
                );
                checked_instructions += 1;
            }
            checked_functions += 1;
        }
    }

    if checked_functions == 0 {
        // Reaching here means llvm-objdump is absent. Say so rather than
        // passing silently on a machine that checked nothing.
        eprintln!("llvm-objdump unavailable, skipped {skipped_objects} objects");
        return;
    }

    eprintln!(
        "checked {checked_instructions} instructions in {checked_functions} functions \
         ({unknown_instructions} opaque, mostly NEON)"
    );
}

/// The normalizer can hide decoder bugs, so test it directly.
#[test]
fn canonical_mnemonic_folds_known_spellings() {
    // Aliases both tools accept for the same encoding.
    for (ours, theirs) in
        [("cmps", "cmp"), ("movw", "mov"), ("movs", "lsrs"), ("adr", "add"), ("rrx", "mov")]
    {
        assert_eq!(
            canonical_mnemonic(ours),
            canonical_mnemonic(theirs),
            "{ours} and {theirs} are the same instruction"
        );
    }
}

#[test]
fn canonical_mnemonic_strips_condition_codes() {
    assert_eq!(canonical_mnemonic("movlo"), "mov");
    assert_eq!(canonical_mnemonic("bxeq"), "bx");
    assert_eq!(canonical_mnemonic("movwlt"), "mov");
}

/// A mnemonic that merely ends in condition letters must survive intact.
#[test]
fn canonical_mnemonic_keeps_lookalike_mnemonics() {
    for mnemonic in ["b", "bl", "ble", "bls", "mov", "cmp", "mul", "push", "pop"] {
        assert_eq!(canonical_mnemonic(mnemonic), mnemonic, "{mnemonic} carries no condition");
    }
}

/// Different instructions must stay different, or the harness proves nothing.
#[test]
fn canonical_mnemonic_keeps_distinct_instructions_apart() {
    assert_ne!(canonical_mnemonic("add"), canonical_mnemonic("sub"));
    assert_ne!(canonical_mnemonic("ldr"), canonical_mnemonic("str"));
    assert_ne!(canonical_mnemonic("mov"), canonical_mnemonic("mul"));
    assert_ne!(canonical_mnemonic("push"), canonical_mnemonic("pop"));
}

#[test]
fn objdump_parser_reads_instruction_lines() {
    let sample = "\
t.o:\tfile format elf32-littlearm

Disassembly of section .text:

00000000 <add>:
       0: e0810000     \tadd\tr0, r1, r0
       4: e12fff1e     \tbx\tlr
";
    let parsed = parse_objdump(sample);
    assert_eq!(
        parsed,
        vec![
            ObjdumpInsn { address: 0, mnemonic: "add".to_string() },
            ObjdumpInsn { address: 4, mnemonic: "bx".to_string() },
        ]
    );
}

/// The backport libraries the operand check reads: three projects, each
/// architecture, by clang and by GCC. They keep their symbols, so each
/// function reads in the instruction set its symbol names.
fn backport_libraries() -> Vec<PathBuf> {
    let root = fixtures_dir().join("backports");
    let mut libraries = Vec::new();
    for project in ["zlib", "lua", "tinyxml2"] {
        for arch in ["arm", "thumb", "aarch64", "mips", "mipsel"] {
            for level in ["O2", "gcc-O2"] {
                let path = root.join(format!("{project}-before/{arch}-{level}/lib.so"));
                if path.exists() {
                    libraries.push(path);
                }
            }
        }
    }
    libraries
}

/// What `llvm-objdump` printed at each address: the mnemonic and the
/// operands. Data that it prints as `.word` is left out.
///
/// Returns `None` when `llvm-objdump` is missing.
fn objdump_file(
    object: &Path,
    triple: &str,
) -> Option<std::collections::HashMap<u64, (String, String)>> {
    let output = Command::new("llvm-objdump")
        .args(["-d", "--no-show-raw-insn", &format!("--triple={triple}")])
        .arg(object)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut lines = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((address, rest)) = line.split_once(':') else { continue };
        let Ok(address) = u64::from_str_radix(address.trim(), 16) else { continue };
        if [".word", ".short", ".byte", "<unknown>"].iter().any(|data| rest.contains(data)) {
            continue;
        }
        let mut fields = rest.split('\t').map(str::trim).filter(|field| !field.is_empty());
        let Some(mnemonic) = fields.next() else { continue };
        let operands = fields.next().unwrap_or_default();
        lines.insert(address, (mnemonic.to_string(), operands.to_string()));
    }
    Some(lines)
}

/// The names `yaxpeax` and this decoder give the MIPS floating point
/// registers, by number: those of the o32 ABI. `llvm-objdump` prints
/// `$f0` and on.
const MIPS_FLOAT_REGISTERS: [&str; 32] = [
    "fv0", "fv0f", "fv1", "fv1f", "ft0", "ft0f", "ft1", "ft1f", "ft2", "ft2f", "ft3", "ft3f",
    "fa0", "fa0f", "fa1", "fa1f", "ft4", "ft4f", "ft5", "ft5f", "fs0", "fs0f", "fs1", "fs1f",
    "fs2", "fs2f", "fs3", "fs3f", "fs4", "fs4f", "fs5", "fs5f",
];

/// The MIPS general registers by number, as this decoder names them.
const MIPS_REGISTERS: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp",
    "ra",
];

/// A number in either tool's spelling: hex or decimal, with a sign.
fn number(token: &str) -> Option<i128> {
    let (negative, digits) = match token.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, token),
    };
    let value = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) => {
            digits.parse().ok()?
        }
        None => return None,
    };
    Some(if negative { -value } else { value })
}

/// Reduce one instruction to a form both tools agree on, wherever they only
/// spell the same encoding differently. Each rule names a spelling, not a
/// fault:
///
/// * A comment, after `@` or `//`, and a symbol in `<>` go.
/// * `.w` and `.n` only name the width of a T32 encoding.
/// * A branch target: this decoder prints the distance from the branch,
///   `$+0x54`, and `llvm-objdump` the address. `adrp` counts from the page.
/// * `#` before a constant, hex against decimal, and a 32-bit constant as
///   signed or not.
/// * The A32 names of `r9` to `r12`: `sb`, `sl`, `fp` and `ip`. MIPS
///   registers by number or by name, and `s8` for `fp`.
/// * Aliases of one encoding: `lsr r0, r1, #2` for `mov r0, r1, lsr 2`,
///   `movw` for `mov`, `adr` for `add rd, pc`, `stmia` for `stm`, `addw`
///   for `add`, `pop {r4}` for `ldr r4, [sp], #4`, `move` for `or` with
///   `zero`, `lo` and `hs` for `cc` and `cs`, and a destination written
///   once where it is also the first source.
/// * A rotation or an extension by 0, which `llvm-objdump` leaves out.
/// * Where a VFP condition goes, `vmovgt.f64` or `vmov.f64gt`, and how a
///   float constant prints.
/// * `trap` for `udf #254`, the code 0 of a MIPS `teq` or `break`, and
///   spaces inside braces.
fn folded(isa: Isa, address: u64, mnemonic: &str, operands: &str) -> String {
    let mips = matches!(isa, Isa::Mips32 | Isa::Mips32Be | Isa::Mips16 | Isa::Mips16Be);
    let mut operands = operands.to_string();
    while let Some(start) = operands.find('<') {
        let end = operands[start..].find('>').map_or(operands.len(), |end| start + end + 1);
        operands.replace_range(start..end, "");
    }
    for comment in ["@", "//"] {
        if let Some(at) = operands.find(comment) {
            operands.truncate(at);
        }
    }
    let mut mnemonic = mnemonic.split_whitespace().next().unwrap_or_default().to_string();
    for width in [".w", ".n"] {
        if let Some(stem) = mnemonic.strip_suffix(width) {
            mnemonic = stem.to_string();
        }
    }
    if let Some(at) = operands.find("$+").or_else(|| operands.find("$-")) {
        let rest = &operands[at + 1..];
        let end = rest.find([',', ' ']).unwrap_or(rest.len());
        if let Some(distance) = number(&rest[..end].replace('+', "")) {
            let from = if mnemonic == "adrp" { address & !0xfff } else { address };
            operands
                .replace_range(at..at + 1 + end, &format!("{:#x}", i128::from(from) + distance));
        }
    }
    let operands = operands.replace('#', "");

    // Each operand, its words folded one by one.
    let word = |word: &str| -> String {
        if mips {
            if let Some(number) = word.strip_prefix("$f").and_then(|n| n.parse::<usize>().ok()) {
                return MIPS_FLOAT_REGISTERS
                    .get(number)
                    .map_or(word.to_string(), |n| n.to_string());
            }
            if let Some(name) = word.strip_prefix('$') {
                return match name.parse::<usize>() {
                    Ok(number) if number < 32 => MIPS_REGISTERS[number].to_string(),
                    _ => name.to_string(),
                };
            }
            if word == "s8" {
                return "fp".to_string();
            }
        } else {
            match word {
                "sb" => return "r9".to_string(),
                "sl" => return "r10".to_string(),
                "fp" => return "r11".to_string(),
                "ip" => return "r12".to_string(),
                _ => {}
            }
        }
        if word.contains('.')
            && let Ok(value) = word.parse::<f64>()
        {
            return format!("{value:?}");
        }
        match number(word) {
            Some(value) if value >= 1 << 63 => (value - (1 << 64)).to_string(),
            Some(value) if isa != Isa::Aarch64 && (1 << 31..1 << 32).contains(&value) => {
                (value - (1 << 32)).to_string()
            }
            Some(value) => value.to_string(),
            None => word.to_lowercase(),
        }
    };
    let mut list: Vec<String> = operands
        .split(',')
        .map(|operand| {
            let mut out = String::new();
            let mut current = String::new();
            for c in operand.trim().chars() {
                let part_of_word = c.is_ascii_alphanumeric()
                    || matches!(c, '_' | '$' | '.')
                    || (matches!(c, '-' | '+')
                        && (current.is_empty() || current.ends_with(['e', 'E'])));
                if part_of_word {
                    current.push(c);
                } else {
                    out += &word(&core::mem::take(&mut current));
                    if !c.is_whitespace() {
                        out.push(c);
                    } else if !out.ends_with(' ') {
                        out.push(' ');
                    }
                }
            }
            out += &word(&current);
            out.trim().to_string()
        })
        .filter(|operand| !operand.is_empty())
        .collect();

    if isa == Isa::Aarch64 && list.first().is_some_and(|first| first.starts_with('w')) {
        for operand in &mut list {
            if let Some(value) = number(operand).filter(|v| (1 << 31..1 << 32).contains(v)) {
                *operand = (value - (1 << 32)).to_string();
            }
        }
    }
    for operand in &mut list {
        for extension in ["sxtw", "uxtw", "sxtx", "uxtx"] {
            *operand = operand.replace(&format!("{extension} 0]"), &format!("{extension}]"));
        }
    }
    for operand in &mut list {
        *operand = operand.replace("{ ", "{").replace(" }", "}");
    }
    if mips {
        if matches!(mnemonic.as_str(), "teq" | "break") && list.last().is_some_and(|l| l == "0") {
            list.pop();
        }
        if mnemonic == "move" {
            mnemonic = "or".to_string();
            list.push("zero".to_string());
        }
    } else {
        for (from, to) in [("cc", "lo"), ("cs", "hs")] {
            if mnemonic.len() > 4
                && let Some(stem) = mnemonic.strip_suffix(from)
            {
                mnemonic = format!("{stem}{to}");
            }
        }
        for (from, to) in
            [("stmia", "stm"), ("ldmia", "ldm"), ("subw", "sub"), ("addw", "add"), ("movw", "mov")]
        {
            if let Some(rest) = mnemonic.strip_prefix(from) {
                mnemonic = format!("{to}{rest}");
            }
        }
        if let Some(rest) = mnemonic.strip_prefix("adr") {
            mnemonic = format!("add{rest}");
            if list.len() == 2 {
                list.insert(1, "pc".to_string());
            }
        }
        // `vmovgt.f64` and `vmov.f64gt`: the condition goes before the
        // sizes.
        if let Some((stem, sizes)) = mnemonic.clone().split_once('.')
            && sizes.len() > 2
            && sizes[sizes.len() - 2..].bytes().all(|byte| byte.is_ascii_lowercase())
        {
            let (sizes, condition) = sizes.split_at(sizes.len() - 2);
            mnemonic = format!("{stem}{condition}.{sizes}");
        }
        if mnemonic == "udf" && list == ["254"] {
            mnemonic = "trap".to_string();
            list.clear();
        }
        if (mnemonic.starts_with("uxt") || mnemonic.starts_with("sxt"))
            && list.last().is_some_and(|last| last == "0" || last == "ror 0")
        {
            list.pop();
        }
        // `mov r0, r1, lsr 2` is `lsr r0, r1, 2`.
        if let Some(rest) = mnemonic.strip_prefix("mov")
            && list.len() == 3
            && let Some((shift, amount)) = list[2].clone().split_once(' ')
            && ["lsl", "lsr", "asr", "ror"].contains(&shift)
        {
            mnemonic = format!("{shift}{rest}");
            list[2] = amount.to_string();
        }
        // `ldr r4, [sp], 4` is `pop {r4}`, and `str lr, [sp, -4]!` is
        // `push {lr}`.
        if list.len() == 3 {
            match (mnemonic.as_str(), list[1].as_str(), list[2].as_str()) {
                ("ldr", "[sp]", "4") => {
                    (mnemonic, list) = ("pop".into(), vec![format!("{{{}}}", list[0])])
                }
                ("str", "[sp", "-4]!") => {
                    (mnemonic, list) = ("push".into(), vec![format!("{{{}}}", list[0])])
                }
                _ => {}
            }
        }
        if list.len() >= 3 && list[0] == list[1] {
            list.remove(1);
        }
    }
    format!("{mnemonic} {}", list.join(", "))
}

/// The operands of each instruction, against `llvm-objdump`.
///
/// Boundaries and mnemonics agree, as [`decoder_agrees_with_objdump`]
/// checks. Operands went unchecked, and four faults of `yaxpeax-arm` 0.4
/// hid in them until a comparison by hand. Here each instruction is folded
/// by [`folded`], and what still differs is counted by instruction set.
/// The counts are locked: a new fault raises one, and a fix lowers one.
/// What is left are faults still unfixed:
///
/// * A32 `smulbb` reads as `smultt`.
/// * AArch64 leaves out `uxtw` on a register that it extends.
/// * The NEON loads and stores this decoder reads leave out the alignment,
///   as `[r3:64]`.
///
/// Another version of LLVM can print otherwise, so this needs the one it
/// was counted with, LLVM 22.
#[test]
fn operands_agree_with_objdump() {
    let libraries = backport_libraries();
    if libraries.is_empty() {
        eprintln!("skipped: run `just backports` first");
        return;
    }
    let mut disagree: std::collections::BTreeMap<String, usize> = Default::default();
    let mut examples: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for path in &libraries {
        let binary = Binary::parse(&std::fs::read(path).expect("readable")).expect("parses");
        let Some(theirs) = objdump_file(path, binary.isa.arch().triple()) else {
            eprintln!("llvm-objdump unavailable, skipped");
            return;
        };
        for function in &binary.functions {
            let isa = binary.isa_of(function);
            let (decoded, _) = decode_all(isa.arch(), &function.code, function.address);
            for insn in decoded.iter().filter(|insn| insn.kind != InsnKind::Unknown) {
                let Some((mnemonic, operands)) = theirs.get(&insn.address) else { continue };
                checked += 1;
                let ours = folded(isa, insn.address, &insn.mnemonic, &insn.operands);
                let them = folded(isa, insn.address, mnemonic, operands);
                if ours != them {
                    *disagree.entry(format!("{isa:?}")).or_default() += 1;
                    let kind = format!("{isa:?} {}", insn.mnemonic);
                    if !examples.iter().any(|example| example.starts_with(&format!("{kind} "))) {
                        examples.push(format!("{kind} {ours}  |  {them}"));
                    }
                }
            }
        }
    }
    eprintln!("checked the operands of {checked} instructions");
    let counts: Vec<(&str, usize)> =
        disagree.iter().map(|(isa, count)| (isa.as_str(), *count)).collect();
    assert_eq!(
        counts,
        KNOWN_OPERAND_DISAGREEMENTS,
        "the operands that differ from llvm-objdump changed; the first:\n{}",
        examples.join("\n")
    );
}

/// What [`operands_agree_with_objdump`] still finds, by instruction set.
const KNOWN_OPERAND_DISAGREEMENTS: &[(&str, usize)] =
    &[("Aarch64", 108), ("Arm32", 3), ("Thumb2", 2)];
