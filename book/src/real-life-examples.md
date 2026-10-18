# Real-Life Examples

Each page uses `hereticus` on a published security fix, in the binaries
that the vendor shipped. It compares the binary before the fix with the
binary after the fix, and shows where the fixed function is in the report.
Each page gives the commands to get the binaries and to do it again.

The binaries are stripped, and each update holds more changes than the
fix. Thus the report also lists functions that the fix did not touch.
The **row of the fix** is the row that a reader gets to before the fix is
found. Lower is better.

| Fix | Binary, release | Build | Row of the fix | Rows |
|-----|-----------------|-------|----------------|------|
| [CVE-2019-19945](./real-life-examples/cve-2019-19945.md) | uhttpd, OpenWrt 18.06.5 to 18.06.6 | AArch64 | 3<!-- from truth_cves: CVE-2019-19945 uhttpd A64 / rank --> | 5<!-- from truth_cves: CVE-2019-19945 uhttpd A64 / rows --> |
| [CVE-2020-7248](./real-life-examples/cve-2020-7248.md) | libubox, OpenWrt 19.07.0 to 19.07.1 | AArch64 | 1<!-- from truth_cves: CVE-2020-7248 libubox A64 / rank --> | 3<!-- from truth_cves: CVE-2020-7248 libubox A64 / rows --> |
| [CVE-2021-30883](./real-life-examples/cve-2021-30883.md) | AppleCLCD, iOS 15.0.1 to 15.0.2 | kext | 1<!-- from truth_cves: CVE-2021-30883 IOMobileFramebuffer / rank --> | 333<!-- from truth_cves: CVE-2021-30883 IOMobileFramebuffer / rows --> |
| [CVE-2024-23265](./real-life-examples/cve-2024-23265.md) | AppleDiskImages2, iOS 17.3.1 to 17.4 | kext | 1<!-- from truth_cves: CVE-2024-23265 AppleDiskImages2 / rank --> | 33<!-- from truth_cves: CVE-2024-23265 AppleDiskImages2 / rows --> |
| [CVE-2025-14282](./real-life-examples/cve-2025-14282.md) | dropbear, OpenWrt 24.10.4 to 24.10.5 | AArch64 | 2<!-- from truth_cves: CVE-2025-14282 dropbear AArch64 / rank --> | 14<!-- from truth_cves: CVE-2025-14282 dropbear AArch64 / rows --> |
| [CVE-2025-24257](./real-life-examples/cve-2025-24257.md) | IOGPUFamily, iOS 18.3.2 to 18.4 | kext | 19<!-- from truth_cves: CVE-2025-24257 IOGPUFamily / rank --> | 403<!-- from truth_cves: CVE-2025-24257 IOGPUFamily / rows --> |
| [CVE-2025-62525](./real-life-examples/cve-2025-62525.md) | the `ltq-ptm` kernel module, OpenWrt 24.10.3 to 24.10.4 | MIPS32 BE | 1<!-- from truth_cves: CVE-2025-62525 ltq-ptm MIPS32 BE / rank --> | 2<!-- from truth_cves: CVE-2025-62525 ltq-ptm MIPS32 BE / rows --> |
| [CVE-2025-62526](./real-life-examples/cve-2025-62526.md) | ubusd, OpenWrt 24.10.3 to 24.10.4 | AArch64 | 5<!-- from truth_cves: CVE-2025-62526 ubusd AArch64 / rank --> | 8<!-- from truth_cves: CVE-2025-62526 ubusd AArch64 / rows --> |
| [CVE-2026-28825](./real-life-examples/cve-2026-28825.md) | smbfs, macOS 26.3.1 to 26.4 | kext | 9<!-- from truth_cves: CVE-2026-28825 smbfs / rank --> | 462<!-- from truth_cves: CVE-2026-28825 smbfs / rows --> |
| [CVE-2026-30873](./real-life-examples/cve-2026-30873.md) | jsonfilter, OpenWrt 24.10.5 to 24.10.6 | AArch64 | 1<!-- from truth_cves: CVE-2026-30873 jsonfilter AArch64 / rank --> | 1<!-- from truth_cves: CVE-2026-30873 jsonfilter AArch64 / rows --> |
| [CVE-2026-30874](./real-life-examples/cve-2026-30874.md) | procd, OpenWrt 24.10.5 to 24.10.6 | AArch64 | 1<!-- from truth_cves: CVE-2026-30874 procd AArch64 / rank --> | 24<!-- from truth_cves: CVE-2026-30874 procd AArch64 / rows --> |
| [CVE-2026-35385](./real-life-examples/cve-2026-35385.md) | dropbear `scp`, OpenWrt 24.10.7 to 24.10.8 | AArch64 | 1<!-- from truth_cves: CVE-2026-35385 dropbear AArch64 / rank --> | 19<!-- from truth_cves: CVE-2026-35385 dropbear AArch64 / rows --> |
| [CVE-2026-53921](./real-life-examples/cve-2026-53921.md) | odhcpd, OpenWrt 24.10.7 to 24.10.8 | AArch64 | 5<!-- from truth_cves: CVE-2026-53921 odhcpd AArch64 / rank --> | 18<!-- from truth_cves: CVE-2026-53921 odhcpd AArch64 / rows --> |
| [CVE-2026-55614](./real-life-examples/cve-2026-55614.md) | uhttpd, OpenWrt 24.10.7 to 24.10.8 | AArch64 | 5<!-- from truth_cves: CVE-2026-55614 uhttpd AArch64 / rank --> | 13<!-- from truth_cves: CVE-2026-55614 uhttpd AArch64 / rows --> |

Most pages also give the rows of other builds, as A32 and MIPS. The
OpenWrt binaries are all stripped with `sstrip`. The Apple binaries are
kernel extensions (kexts), taken out of the kernelcache with `ipsw`.

`hereticus-cli/tests/truth_cves.rs` locks each row, so a change that moves
a fix down fails the tests.
