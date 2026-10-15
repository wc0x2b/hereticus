//! Lock where the report ranks the function each published fix edits.
//!
//! Each case is a fix of `real-life-reports/`, in the binaries that shipped
//! before and after it. The tool runs as a user runs it, with no options, so
//! the rank is the row a reader finds the fix on. `fixtures/cve_binaries.py`
//! fetches the binaries and pins them by their SHA-256.
//!
//! The Apple binaries come from IPSW files, so `just quick-test` skips this
//! test.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A published fix: its name, the binaries before and after it under
/// `~/.cache`, and the function of the first binary that the fix edits, as
/// the report names it.
struct Fix {
    name: &'static str,
    before: &'static str,
    after: &'static str,
    function: &'static str,
}

const FIXES: &[Fix] = &[
    Fix {
        name: "CVE-2021-30883 IOMobileFramebuffer",
        before: "hereticus-apple/cve/15.0.1/19A348__iPhone12,1/kernelcache.release.iPhone12,1",
        after: "hereticus-apple/cve/15.0.2/19A404__iPhone12,1/kernelcache.release.iPhone12,1",
        function: "sub_fffffff009c0b13c",
    },
    Fix {
        name: "CVE-2024-23265 AppleDiskImages2",
        before: "hereticus-apple/cve/17.3.1/com.apple.driver.AppleDiskImages2",
        after: "hereticus-apple/cve/17.4/com.apple.driver.AppleDiskImages2",
        function: "sub_fffffff028a156c8",
    },
    Fix {
        name: "CVE-2025-24257 IOGPUFamily",
        before: "hereticus-apple/cve/18.3.2/com.apple.iokit.IOGPUFamily",
        after: "hereticus-apple/cve/18.4/com.apple.iokit.IOGPUFamily",
        function: "sub_fffffff009a765c0",
    },
    Fix {
        name: "CVE-2026-28825 smbfs",
        before: "hereticus-apple/cve/26.3.1/com.apple.filesystems.smbfs",
        after: "hereticus-apple/cve/25E246/com.apple.filesystems.smbfs",
        function: "_smb2_rq_decompress_read",
    },
    Fix {
        name: "CVE-2025-62526 ubusd AArch64",
        before: "hereticus-openwrt-cve/24.10.3/armsr-armv8/sbin/ubusd",
        after: "hereticus-openwrt-cve/24.10.4/armsr-armv8/sbin/ubusd",
        function: "sub_4a3c",
    },
    Fix {
        name: "CVE-2025-62526 ubusd A32",
        before: "hereticus-openwrt-cve/24.10.3/armsr-armv7/sbin/ubusd",
        after: "hereticus-openwrt-cve/24.10.4/armsr-armv7/sbin/ubusd",
        function: "sub_3e34",
    },
    Fix {
        name: "CVE-2025-62526 ubusd MIPS16e BE",
        before: "hereticus-openwrt-cve/24.10.3/malta-be/sbin/ubusd",
        after: "hereticus-openwrt-cve/24.10.4/malta-be/sbin/ubusd",
        function: "sub_39e0",
    },
    Fix {
        name: "CVE-2025-62526 ubusd MIPS16e LE",
        before: "hereticus-openwrt-cve/24.10.3/malta-le/sbin/ubusd",
        after: "hereticus-openwrt-cve/24.10.4/malta-le/sbin/ubusd",
        function: "sub_3b0c",
    },
    Fix {
        name: "CVE-2025-14282 dropbear AArch64",
        before: "hereticus-openwrt-cve/24.10.4/armsr-armv8/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.5/armsr-armv8/usr/sbin/dropbear",
        function: "sub_15048",
    },
    Fix {
        name: "CVE-2025-14282 dropbear A32",
        before: "hereticus-openwrt-cve/24.10.4/armsr-armv7/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.5/armsr-armv7/usr/sbin/dropbear",
        function: "sub_148b8",
    },
    Fix {
        name: "CVE-2025-14282 dropbear MIPS32 BE",
        before: "hereticus-openwrt-cve/24.10.4/malta-be/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.5/malta-be/usr/sbin/dropbear",
        function: "sub_18eb0",
    },
    Fix {
        name: "CVE-2025-14282 dropbear MIPS32 LE",
        before: "hereticus-openwrt-cve/24.10.4/malta-le/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.5/malta-le/usr/sbin/dropbear",
        function: "sub_190dc",
    },
    Fix {
        name: "CVE-2026-55614 uhttpd AArch64",
        before: "hereticus-openwrt-cve/24.10.7/armsr-armv8/usr/sbin/uhttpd",
        after: "hereticus-openwrt-cve/24.10.8/armsr-armv8/usr/sbin/uhttpd",
        function: "sub_5d78",
    },
    Fix {
        name: "CVE-2026-55614 uhttpd A32",
        before: "hereticus-openwrt-cve/24.10.7/armsr-armv7/usr/sbin/uhttpd",
        after: "hereticus-openwrt-cve/24.10.8/armsr-armv7/usr/sbin/uhttpd",
        function: "sub_4218",
    },
    Fix {
        name: "CVE-2026-55614 uhttpd MIPS16e BE",
        before: "hereticus-openwrt-cve/24.10.7/malta-be/usr/sbin/uhttpd",
        after: "hereticus-openwrt-cve/24.10.8/malta-be/usr/sbin/uhttpd",
        function: "sub_3f74",
    },
    Fix {
        name: "CVE-2026-55614 uhttpd MIPS16e LE",
        before: "hereticus-openwrt-cve/24.10.7/malta-le/usr/sbin/uhttpd",
        after: "hereticus-openwrt-cve/24.10.8/malta-le/usr/sbin/uhttpd",
        function: "sub_3fc4",
    },
    Fix {
        name: "CVE-2026-53921 odhcpd AArch64",
        before: "hereticus-openwrt-cve/24.10.7/armsr-armv8/usr/sbin/odhcpd",
        after: "hereticus-openwrt-cve/24.10.8/armsr-armv8/usr/sbin/odhcpd",
        function: "sub_e12c",
    },
    Fix {
        name: "CVE-2026-53921 odhcpd A32",
        before: "hereticus-openwrt-cve/24.10.7/armsr-armv7/usr/sbin/odhcpd",
        after: "hereticus-openwrt-cve/24.10.8/armsr-armv7/usr/sbin/odhcpd",
        function: "sub_c1b8",
    },
    Fix {
        name: "CVE-2026-53921 odhcpd MIPS16e BE",
        before: "hereticus-openwrt-cve/24.10.7/malta-be/usr/sbin/odhcpd",
        after: "hereticus-openwrt-cve/24.10.8/malta-be/usr/sbin/odhcpd",
        function: "dhcpv6_ia_handle_IAs",
    },
    Fix {
        name: "CVE-2026-53921 odhcpd MIPS16e LE",
        before: "hereticus-openwrt-cve/24.10.7/malta-le/usr/sbin/odhcpd",
        after: "hereticus-openwrt-cve/24.10.8/malta-le/usr/sbin/odhcpd",
        function: "dhcpv6_ia_handle_IAs",
    },
    Fix {
        name: "CVE-2026-35385 dropbear AArch64",
        before: "hereticus-openwrt-cve/24.10.7/armsr-armv8/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.8/armsr-armv8/usr/sbin/dropbear",
        function: "sub_1650c",
    },
    Fix {
        name: "CVE-2026-35385 dropbear A32",
        before: "hereticus-openwrt-cve/24.10.7/armsr-armv7/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.8/armsr-armv7/usr/sbin/dropbear",
        function: "sub_157bc",
    },
    Fix {
        name: "CVE-2026-35385 dropbear MIPS32 BE",
        before: "hereticus-openwrt-cve/24.10.7/malta-be/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.8/malta-be/usr/sbin/dropbear",
        function: "sub_1a378",
    },
    Fix {
        name: "CVE-2026-35385 dropbear MIPS32 LE",
        before: "hereticus-openwrt-cve/24.10.7/malta-le/usr/sbin/dropbear",
        after: "hereticus-openwrt-cve/24.10.8/malta-le/usr/sbin/dropbear",
        function: "sub_1a34c",
    },
    Fix {
        name: "CVE-2025-62525 ltq-ptm MIPS32 BE",
        before: "hereticus-openwrt-cve/24.10.3/lantiq-xrx200/kmod/kmod-ltq-ptm-vr9/ltq_ptm_vr9.ko",
        after: "hereticus-openwrt-cve/24.10.4/lantiq-xrx200/kmod/kmod-ltq-ptm-vr9/ltq_ptm_vr9.ko",
        function: "sub_267c",
    },
    Fix {
        name: "CVE-2026-30874 procd AArch64",
        before: "hereticus-openwrt-cve/24.10.5/armsr-armv8/sbin/procd",
        after: "hereticus-openwrt-cve/24.10.6/armsr-armv8/sbin/procd",
        function: "sub_7630",
    },
    Fix {
        name: "CVE-2026-30874 procd A32",
        before: "hereticus-openwrt-cve/24.10.5/armsr-armv7/sbin/procd",
        after: "hereticus-openwrt-cve/24.10.6/armsr-armv7/sbin/procd",
        function: "sub_5254",
    },
    Fix {
        name: "CVE-2026-30874 procd MIPS32 BE",
        before: "hereticus-openwrt-cve/24.10.5/malta-be/sbin/procd",
        after: "hereticus-openwrt-cve/24.10.6/malta-be/sbin/procd",
        function: "sub_4528",
    },
    Fix {
        name: "CVE-2026-30874 procd MIPS32 LE",
        before: "hereticus-openwrt-cve/24.10.5/malta-le/sbin/procd",
        after: "hereticus-openwrt-cve/24.10.6/malta-le/sbin/procd",
        function: "sub_45b8",
    },
    Fix {
        name: "CVE-2026-30873 jsonfilter AArch64",
        before: "hereticus-openwrt-cve/24.10.5/armsr-armv8/usr/bin/jsonfilter",
        after: "hereticus-openwrt-cve/24.10.6/armsr-armv8/usr/bin/jsonfilter",
        function: "sub_402c48",
    },
    Fix {
        name: "CVE-2026-30873 jsonfilter A32",
        before: "hereticus-openwrt-cve/24.10.5/armsr-armv7/usr/bin/jsonfilter",
        after: "hereticus-openwrt-cve/24.10.6/armsr-armv7/usr/bin/jsonfilter",
        function: "sub_12580",
    },
    Fix {
        name: "CVE-2026-30873 jsonfilter MIPS16e BE",
        before: "hereticus-openwrt-cve/24.10.5/malta-be/usr/bin/jsonfilter",
        after: "hereticus-openwrt-cve/24.10.6/malta-be/usr/bin/jsonfilter",
        function: "sub_401c2c",
    },
    Fix {
        name: "CVE-2026-30873 jsonfilter MIPS16e LE",
        before: "hereticus-openwrt-cve/24.10.5/malta-le/usr/bin/jsonfilter",
        after: "hereticus-openwrt-cve/24.10.6/malta-le/usr/bin/jsonfilter",
        function: "sub_401c2c",
    },
];

fn cache() -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache")
}

/// The rows of the report, one line each.
fn report(fix: &Fix) -> String {
    let [before, after] = [fix.before, fix.after].map(|file| cache().join(file));
    for file in [&before, &after] {
        assert!(file.exists(), "{} is missing, run `just test`", file.display());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_hereticus"))
        .args(["--progress", "never", "--format", "compact"])
        .args([&before, &after])
        .output()
        .expect("the tool runs");
    assert!(output.status.success(), "{}: {}", fix.name, String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).expect("the report is UTF-8")
}

#[test]
fn the_rank_of_each_published_fix_is_locked() {
    let mut out = String::new();
    writeln!(out, "{:36} {:>4} {:>5}  row", "fix", "rank", "rows").unwrap();
    for fix in FIXES {
        let report = report(fix);
        let rows: Vec<&str> = report.lines().collect();
        // Compact rows are tab separated: the change, then the function
        // before.
        let rank = rows.iter().position(|row| row.split('\t').nth(1) == Some(fix.function));
        let (rank, row) = match rank {
            Some(at) => ((at + 1).to_string(), rows[at].replace('\t', " ")),
            None => ("-".to_owned(), String::new()),
        };
        writeln!(out, "{:36} {rank:>4} {:>5}  {row}", fix.name, rows.len()).unwrap();
    }
    insta::assert_snapshot!(out);
}
