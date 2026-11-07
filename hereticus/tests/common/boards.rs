//! The OpenWrt boards whose kernels `tests/openwrt.rs` compares.

use hereticus::obj::Isa;

/// A board of `tests/openwrt.rs`: the name its files carry, the target whose
/// kernel it runs, how its code reads, and where its kernel is linked.
pub struct Board {
    pub name: &'static str,
    pub target: &'static str,
    pub isa: Isa,
    pub kernel_base: u64,
}

pub const BOARDS: &[Board] = &[
    Board {
        name: "arm-ex6100v2",
        target: "ipq40xx-generic",
        isa: Isa::Arm32,
        kernel_base: 0xc020_8000,
    },
    Board {
        name: "mipsbe-eap245v3",
        target: "ath79-generic",
        isa: Isa::Mips32Be,
        kernel_base: 0x8006_0000,
    },
    Board {
        name: "mipsel-r6220",
        target: "ramips-mt7621",
        isa: Isa::Mips32,
        kernel_base: 0x8000_1000,
    },
    Board {
        name: "arm-a385dbap",
        target: "mvebu-cortexa9",
        isa: Isa::Arm32,
        kernel_base: 0xc000_8000,
    },
    Board {
        name: "mipsbe-vr200",
        target: "lantiq-xrx200",
        isa: Isa::Mips32Be,
        kernel_base: 0x8000_2000,
    },
    Board {
        name: "mipsel-mt300nv2",
        target: "ramips-mt76x8",
        isa: Isa::Mips32,
        kernel_base: 0x8000_0000,
    },
];
