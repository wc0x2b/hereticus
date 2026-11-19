//! Take the code out of a firmware image.
//!
//! A vendor ships a kernel compressed, behind a header, often with a small
//! decompressor in front of it. The comparison reads code, so the image must
//! be unpacked first: the decompressor, which runs as it is, and the kernel
//! it holds. These are the containers OpenWrt builds for the boards the tests
//! read:
//!
//! * a zImage, alone or in a FIT image: an ARM decompressor and an xz, gzip
//!   or zstd kernel
//! * a sysupgrade tar, whose `kernel` member is a zImage
//! * a uImage of an LZMA kernel
//! * a uImage of an lzma-loader: a MIPS decompressor and an LZMA kernel
//! * an ELF lzma-loader, as the ath79 boards boot
//! * a TP-Link v2 image: a header, then an LZMA kernel
//!
//! What a container says of where its parts load is kept, as a raw image
//! needs its base.

use std::io::Cursor;

use deku::prelude::*;

/// The magic word of an ARM zImage, at offset 0x24 of it.
const ZIMAGE_MAGIC: [u8; 4] = 0x016f_2818_u32.to_le_bytes();
/// The offset of the magic word in a zImage header. Code comes before it.
const ZIMAGE_MAGIC_OFFSET: usize = 0x24;
/// The magic of an xz stream.
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
/// The magic of a gzip member, with the method byte of deflate.
const GZIP_MAGIC: &[u8] = b"\x1f\x8b\x08";
/// The magic of a zstd frame, little endian.
const ZSTD_MAGIC: &[u8] = b"\x28\xb5\x2f\xfd";
/// The header OpenWrt's LZMA streams start with: the properties byte 0x6d,
/// `-lc1 -lp2`, then a dictionary of 8 MiB.
const LZMA_HEADER: &[u8] = b"\x6d\x00\x00\x80\x00";
/// The magic of a uImage, big endian.
const UIMAGE_MAGIC: [u8; 4] = [0x27, 0x05, 0x19, 0x56];
/// The length of a uImage header.
const UIMAGE_HEADER: usize = 64;
/// The magic and class of a 32-bit big-endian ELF file.
const ELF32_BIG_MAGIC: &[u8] = b"\x7fELF\x01\x02";
/// The version word a TP-Link v2 header opens with.
const TPLINK_V2_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
/// The length of a TP-Link v2 header.
const TPLINK_V2_HEADER: usize = 0x200;
/// The magic of a squashfs image, which follows the kernel.
const SQUASHFS_MAGIC: &[u8] = b"hsqs";

/// The container an image came in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Container {
    ZImage,
    SysupgradeTar,
    UImageKernel,
    UImageLoader,
    ElfLoader,
    TpLinkV2,
}

/// One part of an image, and where it loads where the container says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub bytes: Vec<u8>,
    pub load: Option<u64>,
}

/// What an image held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unpacked {
    pub container: Container,
    /// The decompressor that runs first, where the image has one.
    pub stub: Option<Part>,
    /// The kernel, decompressed.
    pub kernel: Part,
}

/// Why an image could not be unpacked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnpackError {
    /// No container this module reads.
    Unrecognized,
    /// The container is known, but a part it should hold is not there.
    Missing(&'static str),
    /// No compressed stream of the kind expected decodes.
    NoStream(&'static str),
}

impl core::fmt::Display for UnpackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unrecognized => write!(f, "no firmware container this tool reads"),
            Self::Missing(what) => write!(f, "the image holds no {what}"),
            Self::NoStream(kind) => write!(f, "no {kind} stream in the image decodes"),
        }
    }
}

impl std::error::Error for UnpackError {}

/// The fields of a zImage header that tell where the zImage ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct ZImageHeader {
    #[deku(pad_bytes_before = "ZIMAGE_MAGIC_OFFSET", assert_eq = "ZIMAGE_MAGIC")]
    magic: [u8; 4],
    /// The address the zImage was linked at, 0 where it runs from anywhere.
    start: u32,
    /// The address after the zImage. With a start of 0, this is its length.
    end: u32,
}

/// The header of a uImage, as U-Boot's `image_header` gives it.
#[derive(Clone, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big", magic = b"\x27\x05\x19\x56")]
struct UImageHeader {
    header_crc: u32,
    time: u32,
    /// The length of the body that follows the header.
    size: u32,
    load: u32,
    entry: u32,
    data_crc: u32,
    os: u8,
    arch: u8,
    kind: u8,
    compression: UImageCompression,
    name: [u8; 32],
}

/// The compression of a uImage body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", ctx = "_: deku::ctx::Endian")]
enum UImageCompression {
    #[deku(id = 0)]
    None,
    #[deku(id = 1)]
    Gzip,
    #[deku(id = 2)]
    Bzip2,
    #[deku(id = 3)]
    Lzma,
    #[deku(id = 4)]
    Lzo,
    #[deku(id = 5)]
    Lz4,
    #[deku(id = 6)]
    Zstd,
    #[deku(id_pat = "_")]
    Other(u8),
}

/// The field of a 32-bit big-endian ELF header that gives where the program
/// headers start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big", magic = b"\x7fELF\x01\x02")]
struct Elf32Header {
    #[deku(pad_bytes_before = "22")]
    program_headers: u32,
}

/// A program header of a 32-bit big-endian ELF file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct Elf32ProgramHeader {
    kind: u32,
    offset: u32,
    address: u32,
    physical_address: u32,
    file_size: u32,
    memory_size: u32,
    flags: u32,
    align: u32,
}

/// The `T` that `bytes` open with, or `None` where they do not hold one.
fn parse<'a, T: DekuContainerRead<'a>>(bytes: &'a [u8]) -> Option<T> {
    T::from_bytes((bytes, 0)).ok().map(|(_, value)| value)
}

/// Unpack a firmware image.
///
/// See RESEARCH.md, A18.
pub fn unpack(image: &[u8]) -> Result<Unpacked, UnpackError> {
    if image.get(257..262) == Some(b"ustar") {
        let kernel = tar_member(image, "/kernel").ok_or(UnpackError::Missing("kernel"))?;
        let unpacked = zimage(kernel)?;
        return Ok(Unpacked { container: Container::SysupgradeTar, ..unpacked });
    }
    if image.starts_with(&UIMAGE_MAGIC) {
        return uimage(image);
    }
    if image.starts_with(ELF32_BIG_MAGIC) {
        return elf_loader(image);
    }
    if image.starts_with(&TPLINK_V2_VERSION) && image.get(4..12) == Some(b"ver. 1.0") {
        return tplink_v2(image);
    }
    if find(image, &ZIMAGE_MAGIC, 0).is_some() {
        return zimage(image);
    }
    Err(UnpackError::Unrecognized)
}

/// Split a zImage, wherever it sits in `image`, into its decompressor and
/// the kernel it holds. The zImage gives its own length.
fn zimage(image: &[u8]) -> Result<Unpacked, UnpackError> {
    let missing = UnpackError::Missing("zImage");
    let magic = find(image, &ZIMAGE_MAGIC, 0).ok_or(missing.clone())?;
    let start = magic.checked_sub(ZIMAGE_MAGIC_OFFSET).ok_or(missing.clone())?;
    let header: ZImageHeader = parse(&image[start..]).ok_or(missing.clone())?;
    let length = header.end as usize;
    let zimage = image.get(start..start + length).ok_or(missing)?;
    // The kernel's build picks the compression. OpenWrt picks xz, and most
    // other builds gzip or zstd. The stub holds the code of its own
    // decompressor only, so the first stream of any kind that decodes is
    // the kernel.
    let (payload, kernel) = [Stream::Xz, Stream::Gzip, Stream::Zstd]
        .into_iter()
        .filter_map(|kind| first_stream(zimage, 0, kind).ok())
        .min_by_key(|&(payload, _)| payload)
        .ok_or(UnpackError::NoStream("xz, gzip or zstd"))?;
    Ok(Unpacked {
        container: Container::ZImage,
        stub: Some(Part { bytes: zimage[..payload].to_vec(), load: None }),
        kernel: Part { bytes: kernel, load: None },
    })
}

/// A uImage holds an LZMA kernel, or, uncompressed, an lzma-loader: a
/// decompressor with an LZMA kernel inside it.
fn uimage(image: &[u8]) -> Result<Unpacked, UnpackError> {
    let header: UImageHeader = parse(image).ok_or(UnpackError::Missing("uImage header"))?;
    let load = Some(u64::from(header.load));
    let body = image
        .get(UIMAGE_HEADER..UIMAGE_HEADER + header.size as usize)
        .ok_or(UnpackError::Missing("uImage body"))?;
    let (payload, kernel) = first_stream(body, 0, Stream::Lzma)?;
    if header.compression == UImageCompression::Lzma {
        return Ok(Unpacked {
            container: Container::UImageKernel,
            stub: None,
            kernel: Part { bytes: kernel, load },
        });
    }
    Ok(Unpacked {
        container: Container::UImageLoader,
        stub: Some(Part { bytes: body[..payload].to_vec(), load }),
        kernel: Part { bytes: kernel, load: None },
    })
}

/// Split a 32-bit big-endian ELF lzma-loader into its code and the kernel
/// it holds. The first program header loads both together.
fn elf_loader(image: &[u8]) -> Result<Unpacked, UnpackError> {
    let missing = UnpackError::Missing("program header");
    let header: Elf32Header = parse(image).ok_or(missing.clone())?;
    let program: Elf32ProgramHeader =
        image.get(header.program_headers as usize..).and_then(parse).ok_or(missing)?;
    let (offset, size) = (program.offset as usize, program.file_size as usize);
    let loaded = image.get(offset..offset + size).ok_or(UnpackError::Missing("loader"))?;
    let (payload, kernel) = first_stream(loaded, 0, Stream::Lzma)?;
    Ok(Unpacked {
        container: Container::ElfLoader,
        stub: Some(Part { bytes: loaded[..payload].to_vec(), load: Some(program.address.into()) }),
        kernel: Part { bytes: kernel, load: None },
    })
}

/// A TP-Link v2 image: a header, then an LZMA kernel up to the root
/// filesystem.
fn tplink_v2(image: &[u8]) -> Result<Unpacked, UnpackError> {
    let rootfs = find(image, SQUASHFS_MAGIC, TPLINK_V2_HEADER)
        .ok_or(UnpackError::Missing("root filesystem"))?;
    let (_, kernel) = first_stream(&image[..rootfs], TPLINK_V2_HEADER, Stream::Lzma)?;
    Ok(Unpacked {
        container: Container::TpLinkV2,
        stub: None,
        kernel: Part { bytes: kernel, load: None },
    })
}

/// The kinds of compressed stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stream {
    /// The `.lzma` format, as OpenWrt's lzma-loader and uImages hold.
    Lzma,
    /// The `.xz` format, as an ARM zImage of OpenWrt holds.
    Xz,
    /// A gzip member, as most other ARM zImages hold.
    Gzip,
    /// A zstd frame.
    Zstd,
}

impl Stream {
    /// The bytes a stream of this kind opens with.
    fn magic(self) -> &'static [u8] {
        match self {
            Self::Lzma => LZMA_HEADER,
            Self::Xz => XZ_MAGIC,
            Self::Gzip => GZIP_MAGIC,
            Self::Zstd => ZSTD_MAGIC,
        }
    }

    /// The name of this kind, as an error gives it.
    fn name(self) -> &'static str {
        match self {
            Self::Lzma => "LZMA",
            Self::Xz => "xz",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }

    /// What the stream at the start of `data` decodes to, or `None` where
    /// it does not decode.
    fn decode(self, data: &[u8]) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut out = Vec::new();
        match self {
            Self::Lzma => lzma_rs::lzma_decompress(&mut Cursor::new(data), &mut out).ok()?,
            Self::Xz => return xz_decompress(data),
            // A gzip member says where it ends, and what follows it, as
            // the size the zImage appends, is not read.
            Self::Gzip => drop(flate2::read::GzDecoder::new(data).read_to_end(&mut out).ok()?),
            Self::Zstd => {
                let mut decoder = ruzstd::decoding::StreamingDecoder::new(data).ok()?;
                decoder.read_to_end(&mut out).ok()?;
            }
        }
        Some(out)
    }
}

/// The first stream of `kind` at or after `start` that decodes, by its
/// offset and what it decodes to.
///
/// The magic alone is not enough: a decompressor holds its own format's
/// magic as a constant, so the first match can sit inside the stub. The
/// ARM stub of the tests does exactly this, 231 bytes before its payload.
fn first_stream(data: &[u8], start: usize, kind: Stream) -> Result<(usize, Vec<u8>), UnpackError> {
    let mut from = start;
    while let Some(offset) = find(data, kind.magic(), from) {
        if let Some(decoded) = kind.decode(&data[offset..]) {
            return Ok((offset, decoded));
        }
        from = offset + 1;
    }
    Err(UnpackError::NoStream(kind.name()))
}

/// Decode the first xz stream of `data`.
///
/// `lzma-rs` decodes the LZMA2 inside but no branch filter, and the kernel
/// in an ARM zImage is filtered for ARM: each `bl` holds an absolute target,
/// which compresses better. So the blocks are read here, their LZMA2 decoded,
/// and the branch filter undone. Other filters are refused.
fn xz_decompress(data: &[u8]) -> Option<Vec<u8>> {
    /// The filter ID of LZMA2 in the xz format.
    const LZMA2: u64 = 0x21;
    /// The length of the stream header.
    const STREAM_HEADER: usize = 12;
    /// The length of the CRC32 that ends a block header.
    const BLOCK_HEADER_CRC: usize = 4;

    let stream: XzStreamHeader = parse(data)?;
    let mut at = STREAM_HEADER;
    let mut out = Vec::new();
    loop {
        let size_byte = *data.get(at)?;
        // A zero byte opens the index, which ends the blocks.
        if size_byte == 0 {
            return Some(out);
        }
        let header_size = (usize::from(size_byte) + 1) * 4;
        let header = data.get(at..at + header_size)?;
        // The fields end before the padding and the CRC32, so a filter that
        // runs into either one is refused.
        let block: XzBlockHeader = parse(&header[1..header_size - BLOCK_HEADER_CRC])?;
        let mut branches = Vec::new();
        for filter in &block.filters {
            match filter.id.0 {
                LZMA2 => {}
                id => branches.push(BranchFilter::of(id, &filter.properties)?),
            }
        }

        let start = at + header_size;
        let mut input = Cursor::new(data.get(start..)?);
        let mut block = Vec::new();
        lzma_rs::lzma2_decompress(&mut input, &mut block).ok()?;
        // The filters run in the order the header lists them on the way in,
        // so they are undone the other way.
        for filter in branches.iter().rev() {
            filter.undo(&mut block);
        }
        out.extend_from_slice(&block);

        let compressed = usize::try_from(input.position()).ok()?;
        at = start + compressed.next_multiple_of(4) + stream.check.size();
    }
}

/// The header that opens an xz stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(magic = b"\xfd7zXZ\x00")]
struct XzStreamHeader {
    #[deku(pad_bytes_before = "1", pad_bits_before = "4")]
    check: XzCheck,
    #[deku(endian = "little")]
    crc: u32,
}

/// The check that follows each block of an xz stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", bits = 4)]
enum XzCheck {
    #[deku(id = 0x00)]
    None,
    #[deku(id = 0x01)]
    Crc32,
    #[deku(id = 0x04)]
    Crc64,
    #[deku(id = 0x0a)]
    Sha256,
}

impl XzCheck {
    /// The length of the check, in bytes.
    fn size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc32 => 4,
            Self::Crc64 => 8,
            Self::Sha256 => 32,
        }
    }
}

/// Whether an optional field of an xz block header is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", bits = 1)]
enum Presence {
    #[deku(id = 0)]
    Absent,
    #[deku(id = 1)]
    Present,
}

/// The fields of an xz block header after its size byte, up to its padding.
#[derive(Clone, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
struct XzBlockHeader {
    uncompressed_size_field: Presence,
    compressed_size_field: Presence,
    #[deku(bits = 4, assert_eq = "0")]
    reserved: u8,
    /// The number of filters, less one.
    #[deku(bits = 2)]
    last_filter: u8,
    #[deku(cond = "*compressed_size_field == Presence::Present")]
    compressed_size: Option<Varint>,
    #[deku(cond = "*uncompressed_size_field == Presence::Present")]
    uncompressed_size: Option<Varint>,
    #[deku(count = "usize::from(*last_filter) + 1")]
    filters: Vec<XzFilter>,
}

/// One filter of an xz block header: its ID and its properties.
#[derive(Clone, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
struct XzFilter {
    id: Varint,
    properties_size: Varint,
    #[deku(count = "properties_size.0")]
    properties: Vec<u8>,
}

/// A variable-length integer of the xz format: seven bits a byte, low bits
/// first, with the top bit set on each byte but the last. It takes at most
/// nine bytes, so it holds at most 63 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
struct Varint(
    #[deku(reader = "read_varint(deku::reader)", writer = "write_varint(*field_0, deku::writer)")]
    u64,
);

/// The most bytes a varint of the xz format takes.
const VARINT_MAX_BYTES: u32 = 9;

fn read_varint<R: deku::no_std_io::Read + deku::no_std_io::Seek>(
    reader: &mut Reader<R>,
) -> Result<u64, DekuError> {
    let mut value = 0u64;
    for index in 0..VARINT_MAX_BYTES {
        let byte = u8::from_reader_with_ctx(reader, ())?;
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(DekuError::Parse("an xz varint is longer than nine bytes".into()))
}

fn write_varint<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
    value: u64,
    writer: &mut Writer<W>,
) -> Result<(), DekuError> {
    if value >> (VARINT_MAX_BYTES * 7) != 0 {
        return Err(DekuError::InvalidParam("an xz varint holds at most 63 bits".into()));
    }
    let mut rest = value;
    loop {
        let low = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest == 0 {
            return low.to_writer(writer, ());
        }
        (low | 0x80).to_writer(writer, ())?;
    }
}

/// A branch filter of the xz format, and the address its data starts at.
///
/// Each filter finds the calls and jumps of one instruction set, which hold
/// a target relative to themselves, and writes the target as an absolute
/// address, which repeats where many calls reach one function and so
/// compresses better. The rules are those of liblzma, which the kernel's
/// own decoder copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BranchFilter {
    kind: BranchKind,
    /// The address of the first byte, as the filter counts it.
    start: u32,
}

/// The instruction set a branch filter reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BranchKind {
    X86,
    PowerPc,
    Arm,
    ArmThumb,
    Sparc,
    Arm64,
}

impl BranchFilter {
    /// The filter with the xz ID `id` and `properties`, or `None` for a
    /// filter this does not read. The properties are none, or the start
    /// address as four bytes, little endian.
    fn of(id: u64, properties: &[u8]) -> Option<Self> {
        let kind = match id {
            0x04 => BranchKind::X86,
            0x05 => BranchKind::PowerPc,
            0x07 => BranchKind::Arm,
            0x08 => BranchKind::ArmThumb,
            0x09 => BranchKind::Sparc,
            0x0a => BranchKind::Arm64,
            _ => return None,
        };
        let start = match properties {
            [] => 0,
            &[a, b, c, d] => u32::from_le_bytes([a, b, c, d]),
            _ => return None,
        };
        Some(Self { kind, start })
    }

    /// Take each target in `data` back from absolute to relative.
    fn undo(self, data: &mut [u8]) {
        match self.kind {
            BranchKind::X86 => undo_x86(data, self.start),
            BranchKind::PowerPc => undo_powerpc(data, self.start),
            BranchKind::Arm => undo_arm(data, self.start),
            BranchKind::ArmThumb => undo_arm_thumb(data, self.start),
            BranchKind::Sparc => undo_sparc(data, self.start),
            BranchKind::Arm64 => undo_arm64(data, self.start),
        }
    }
}

/// The address of byte `at` of data that starts at `start`, as the
/// filters count it: in 32 bits, wrapping.
fn address(start: u32, at: usize) -> u32 {
    start.wrapping_add(at as u32)
}

/// Undo the ARM filter: each `bl` holds its target as an address, and the
/// filter takes the instruction's own address, read 8 bytes ahead, back
/// out.
fn undo_arm(data: &mut [u8], start: u32) {
    for at in (0..data.len().saturating_sub(3)).step_by(4) {
        if data[at + 3] != 0xeb {
            continue;
        }
        let absolute = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], 0]) << 2;
        let relative = absolute.wrapping_sub(address(start, at).wrapping_add(8)) >> 2;
        data[at..at + 3].copy_from_slice(&relative.to_le_bytes()[..3]);
    }
}

/// Undo the ARM-Thumb filter: each `bl`, as its two halfwords, holds its
/// target as an address, read 4 bytes ahead.
fn undo_arm_thumb(data: &mut [u8], start: u32) {
    let mut at = 0;
    while at + 4 <= data.len() {
        let is_call = data[at + 1] & 0xf8 == 0xf0 && data[at + 3] & 0xf8 == 0xf8;
        if !is_call {
            at += 2;
            continue;
        }
        let absolute = ((u32::from(data[at + 1]) & 7) << 19
            | u32::from(data[at]) << 11
            | (u32::from(data[at + 3]) & 7) << 8
            | u32::from(data[at + 2]))
            << 1;
        let relative = absolute.wrapping_sub(address(start, at).wrapping_add(4)) >> 1;
        data[at + 1] = 0xf0 | ((relative >> 19) & 7) as u8;
        data[at] = (relative >> 11) as u8;
        data[at + 3] = 0xf8 | ((relative >> 8) & 7) as u8;
        data[at + 2] = relative as u8;
        at += 4;
    }
}

/// Undo the ARM64 filter: each `bl` holds its target as an address, and
/// each `adrp` that reaches less than 512 MiB away holds its page as one.
fn undo_arm64(data: &mut [u8], start: u32) {
    for at in (0..data.len().saturating_sub(3)).step_by(4) {
        let word: [u8; 4] = data[at..at + 4].try_into().expect("four bytes");
        let instruction = u32::from_le_bytes(word);
        let here = address(start, at);
        let restored = if instruction >> 26 == 0x25 {
            0x9400_0000 | (instruction.wrapping_sub(here >> 2) & 0x03ff_ffff)
        } else if instruction & 0x9f00_0000 == 0x9000_0000 {
            let absolute = (instruction >> 29) & 3 | (instruction >> 3) & 0x001f_fffc;
            if absolute.wrapping_add(0x0002_0000) & 0x001c_0000 != 0 {
                continue;
            }
            let relative = absolute.wrapping_sub(here >> 12);
            instruction & 0x9000_001f
                | (relative & 3) << 29
                | (relative & 0x0003_fffc) << 3
                | 0u32.wrapping_sub(relative & 0x0002_0000) & 0x00e0_0000
        } else {
            continue;
        };
        data[at..at + 4].copy_from_slice(&restored.to_le_bytes());
    }
}

/// Undo the PowerPC filter, big endian: each `bl` holds its target as an
/// address.
fn undo_powerpc(data: &mut [u8], start: u32) {
    for at in (0..data.len().saturating_sub(3)).step_by(4) {
        if data[at] >> 2 != 0x12 || data[at + 3] & 3 != 1 {
            continue;
        }
        let word: [u8; 4] = data[at..at + 4].try_into().expect("four bytes");
        let absolute = u32::from_be_bytes(word) & 0x03ff_fffc;
        let relative = absolute.wrapping_sub(address(start, at));
        let restored = 0x4800_0000 | relative & 0x03ff_fffc | 1;
        data[at..at + 4].copy_from_slice(&restored.to_be_bytes());
    }
}

/// Undo the SPARC filter, big endian: each `call` holds its target as an
/// address.
fn undo_sparc(data: &mut [u8], start: u32) {
    for at in (0..data.len().saturating_sub(3)).step_by(4) {
        let is_call = (data[at] == 0x40 && data[at + 1] & 0xc0 == 0x00)
            || (data[at] == 0x7f && data[at + 1] & 0xc0 == 0xc0);
        if !is_call {
            continue;
        }
        let word: [u8; 4] = data[at..at + 4].try_into().expect("four bytes");
        let absolute = u32::from_be_bytes(word) << 2;
        let relative = absolute.wrapping_sub(address(start, at)) >> 2;
        let sign = 0u32.wrapping_sub((relative >> 22) & 1) << 22 & 0x3fff_ffff;
        let restored = sign | relative & 0x003f_ffff | 0x4000_0000;
        data[at..at + 4].copy_from_slice(&restored.to_be_bytes());
    }
}

/// Undo the x86 filter: each `call` and `jmp` with a 32-bit offset, `e8`
/// and `e9`, holds its target as an address where the offset reads as a
/// near one, with a high byte of `00` or `ff`.
///
/// Which bytes the filter took as such an opcode depends on the opcodes it
/// met in the 4 bytes before, as liblzma keeps them in a mask.
fn undo_x86(data: &mut [u8], start: u32) {
    /// Whether a mask of the bytes before lets an opcode be read.
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    /// Which byte of the target a mask says to test again.
    const BYTE_TO_TEST: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
    /// The bytes of the instruction: the opcode and its offset.
    const LENGTH: usize = 5;
    let is_near = |byte: u8| byte == 0x00 || byte == 0xff;

    if data.len() < LENGTH {
        return;
    }
    let mut mask: u32 = 0;
    let mut previous = start.wrapping_sub(LENGTH as u32);
    let mut at = 0;
    while at <= data.len() - LENGTH {
        if data[at] != 0xe8 && data[at] != 0xe9 {
            at += 1;
            continue;
        }
        let here = address(start, at);
        let since = here.wrapping_sub(previous);
        previous = here;
        if since > LENGTH as u32 {
            mask = 0;
        } else {
            for _ in 0..since {
                mask &= 0x77;
                mask <<= 1;
            }
        }
        let high = data[at + 4];
        if is_near(high) && ALLOWED[((mask >> 1) & 7) as usize] && (mask >> 1) < 0x10 {
            let mut source = u32::from_le_bytes([data[at + 1], data[at + 2], data[at + 3], high]);
            let target = loop {
                let target = source.wrapping_sub(here.wrapping_add(LENGTH as u32));
                if mask == 0 {
                    break target;
                }
                let byte = BYTE_TO_TEST[(mask >> 1) as usize];
                if !is_near((target >> (24 - byte * 8)) as u8) {
                    break target;
                }
                source = target ^ ((1u32 << (32 - byte * 8)) - 1);
            };
            data[at + 4] = !(((target >> 24) & 1) as u8).wrapping_sub(1);
            data[at + 1..at + 4].copy_from_slice(&target.to_le_bytes()[..3]);
            at += LENGTH;
            mask = 0;
        } else {
            at += 1;
            mask |= 1;
            if is_near(high) {
                mask |= 0x10;
            }
        }
    }
}

/// The bytes of the first member of a tar whose name ends with `suffix`.
fn tar_member<'a>(tar: &'a [u8], suffix: &str) -> Option<&'a [u8]> {
    /// The length of a tar header, and of each block.
    const BLOCK: usize = 512;
    let mut at = 0;
    while let Some(block) = tar.get(at..at + BLOCK) {
        if block.iter().all(|&byte| byte == 0) {
            return None;
        }
        let header: TarHeader = parse(block)?;
        let size = header.size()?;
        let body = at + BLOCK;
        if header.name()?.ends_with(suffix) {
            return tar.get(body..body + size);
        }
        at = body + size.next_multiple_of(BLOCK);
    }
    None
}

/// The fields of a tar header that give a member's name and size.
#[derive(Clone, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
struct TarHeader {
    /// The name, ended by a zero byte where it is shorter than the field.
    name: [u8; 100],
    /// The size in octal digits, ended by a zero byte or a space.
    #[deku(pad_bytes_before = "24")]
    size: [u8; 12],
}

impl TarHeader {
    fn name(&self) -> Option<&str> {
        let end = self.name.iter().position(|&byte| byte == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).ok()
    }

    fn size(&self) -> Option<usize> {
        let digits = core::str::from_utf8(&self.size).ok()?;
        usize::from_str_radix(digits.trim_matches(|c: char| c == '\0' || c == ' '), 8).ok()
    }
}

/// The offset of the first `needle` in `haystack` at or after `from`.
fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| offset + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arm_filter_takes_each_call_back_to_its_own_address() {
        // A `bl` at 0x8 whose filtered target is 0x108 holds the offset
        // (0x108 - 0x8 - 8) / 4 again.
        let mut data = vec![0; 8];
        data.extend_from_slice(&[0x42, 0x00, 0x00, 0xeb]);
        undo_arm(&mut data, 0);
        assert_eq!(data[8..], [0x3e, 0x00, 0x00, 0xeb]);
        // A word that is no `bl` stays.
        let mut other = vec![0x42, 0x00, 0x00, 0xea];
        undo_arm(&mut other, 0);
        assert_eq!(other, [0x42, 0x00, 0x00, 0xea]);
    }

    /// Each branch filter undoes what `xz` 5.8 wrote with it: the streams
    /// that `tests/data/make.sh` writes from the same payload.
    #[test]
    fn each_branch_filter_gives_back_the_bytes_xz_filtered() {
        let payload = include_bytes!("../tests/data/payload.bin");
        let streams: [(&str, &[u8]); 7] = [
            ("x86", include_bytes!("../tests/data/x86.xz")),
            ("powerpc", include_bytes!("../tests/data/powerpc.xz")),
            ("arm", include_bytes!("../tests/data/arm.xz")),
            ("arm, from 4096", include_bytes!("../tests/data/arm-start.xz")),
            ("armthumb", include_bytes!("../tests/data/armthumb.xz")),
            ("arm64", include_bytes!("../tests/data/arm64.xz")),
            ("sparc", include_bytes!("../tests/data/sparc.xz")),
        ];
        for (filter, stream) in streams {
            assert_eq!(xz_decompress(stream).as_deref(), Some(&payload[..]), "{filter}");
        }
    }

    /// A zImage of `stream`: a stub of 0x200 bytes that holds a gzip magic
    /// of its own, as a decompressor holds the constants of its format, then
    /// the stream and the size of the kernel, as the kernel's build appends
    /// it.
    fn zimage_of(stream: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 0x200];
        image[0x100..0x103].copy_from_slice(GZIP_MAGIC);
        image.extend_from_slice(stream);
        image.extend_from_slice(&8192u32.to_le_bytes());
        let end = image.len() as u32;
        let header = ZImageHeader { magic: ZIMAGE_MAGIC, start: 0, end };
        let header = header.to_bytes().expect("the header writes");
        image[..header.len()].copy_from_slice(&header);
        image
    }

    #[test]
    fn a_zimage_holds_an_xz_a_gzip_or_a_zstd_kernel() {
        let payload = include_bytes!("../tests/data/payload.bin");
        let streams: [(&str, &[u8]); 3] = [
            ("xz", include_bytes!("../tests/data/arm.xz")),
            ("gzip", include_bytes!("../tests/data/payload.gz")),
            ("zstd", include_bytes!("../tests/data/payload.zst")),
        ];
        for (kind, stream) in streams {
            let unpacked = unpack(&zimage_of(stream)).expect(kind);
            assert_eq!(unpacked.container, Container::ZImage, "{kind}");
            assert_eq!(unpacked.kernel.bytes, payload, "{kind}");
            let stub = unpacked.stub.expect("a zImage has a stub");
            assert_eq!(stub.bytes.len(), 0x200, "{kind}: the stub ends where the stream starts");
        }
    }

    #[test]
    fn a_zimage_with_no_stream_that_decodes_says_so() {
        let gzip = include_bytes!("../tests/data/payload.gz");
        let mut cut = zimage_of(&gzip[..gzip.len() / 2]);
        cut.truncate(cut.len() - 4);
        let length = cut.len() as u32;
        cut[0x2c..0x30].copy_from_slice(&length.to_le_bytes());
        assert_eq!(unpack(&cut), Err(UnpackError::NoStream("xz, gzip or zstd")));
    }

    #[test]
    fn a_filter_this_does_not_read_is_refused() {
        assert_eq!(BranchFilter::of(0x06, &[]), None, "IA-64");
        assert_eq!(BranchFilter::of(0x03, &[0]), None, "delta");
        assert_eq!(BranchFilter::of(0x07, &[1, 2]), None, "a start of two bytes");
        assert_eq!(
            BranchFilter::of(0x07, &[0, 0x10, 0, 0]),
            Some(BranchFilter { kind: BranchKind::Arm, start: 0x1000 })
        );
    }

    #[test]
    fn a_varint_reads_seven_bits_a_byte() {
        assert_eq!(parse(&[0x21]), Some(Varint(0x21)));
        assert_eq!(parse(&[0x80, 0x01]), Some(Varint(0x80)));
        assert_eq!(parse::<Varint>(&[0x80]), None, "cut short");
        assert_eq!(parse::<Varint>(&[0xff; 10]), None, "longer than nine bytes");
    }

    #[test]
    fn a_varint_writes_back_the_bytes_it_reads() {
        bolero::check!().with_type::<u64>().for_each(|&value| {
            let value = value >> 1;
            let bytes = Varint(value).to_bytes().expect("a varint writes");
            assert_eq!(parse(&bytes), Some(Varint(value)));
        });
        assert!(Varint(1 << 63).to_bytes().is_err(), "64 bits do not fit");
    }

    #[test]
    fn an_xz_stream_header_gives_the_check_of_its_blocks() {
        let header = |check: u8| [b"\xfd7zXZ\x00".as_slice(), &[0, check], &[0; 4]].concat();
        assert_eq!(parse::<XzStreamHeader>(&header(0x04)).map(|h| h.check), Some(XzCheck::Crc64));
        assert_eq!(parse::<XzStreamHeader>(&header(0x02)), None, "a check xz does not define");
        assert_eq!(parse::<XzStreamHeader>(&header(0x04)[1..]), None, "no magic");
    }

    #[test]
    fn an_xz_block_header_reads_its_sizes_and_filters() {
        // Both sizes, then two filters: ARM from 0x1000, and LZMA2.
        let bytes = [0xc1, 0x05, 0x80, 0x01, 0x07, 0x04, 0x00, 0x10, 0x00, 0x00, 0x21, 0x01, 0x16];
        let block: XzBlockHeader = parse(&bytes).expect("the header reads");
        assert_eq!(block.compressed_size, Some(Varint(5)));
        assert_eq!(block.uncompressed_size, Some(Varint(0x80)));
        let ids: Vec<u64> = block.filters.iter().map(|filter| filter.id.0).collect();
        assert_eq!(ids, [0x07, 0x21]);
        assert_eq!(block.filters[0].properties, [0x00, 0x10, 0x00, 0x00]);
        assert_eq!(block.to_bytes().expect("the header writes"), bytes);

        assert_eq!(parse::<XzBlockHeader>(&[0x04, 0x21, 0x01]), None, "a reserved bit is set");
        assert_eq!(parse::<XzBlockHeader>(&[0x00, 0x21, 0x05, 0x16]), None, "properties cut");
    }

    #[test]
    fn a_uimage_header_reads_its_body_size_load_address_and_compression() {
        let header = UImageHeader {
            header_crc: 0,
            time: 0,
            size: 0x1234,
            load: 0x8000_0000,
            entry: 0x8000_0000,
            data_crc: 0,
            os: 5,
            arch: 5,
            kind: 2,
            compression: UImageCompression::Lzma,
            name: [0; 32],
        };
        let bytes = header.to_bytes().expect("the header writes");
        assert_eq!(bytes.len(), UIMAGE_HEADER);
        assert!(bytes.starts_with(&UIMAGE_MAGIC));
        assert_eq!(parse(&bytes), Some(header));
        assert_eq!(parse::<UImageHeader>(&bytes[..UIMAGE_HEADER - 1]), None, "cut short");

        let mut other = bytes;
        other[31] = 0x42;
        let compression = parse::<UImageHeader>(&other).map(|h| h.compression);
        assert_eq!(compression, Some(UImageCompression::Other(0x42)));
    }

    #[test]
    fn an_elf_loader_reads_its_first_program_header() {
        let program = Elf32ProgramHeader {
            kind: 1,
            offset: 0x60,
            address: 0x8006_0000,
            physical_address: 0x8006_0000,
            file_size: 4,
            memory_size: 4,
            flags: 7,
            align: 0x10,
        };
        let mut image = Elf32Header { program_headers: 0x40 }.to_bytes().expect("ELF header");
        image.resize(0x40, 0);
        image.extend(program.to_bytes().expect("the program header writes"));
        image.extend(b"code");
        assert_eq!(&image[28..32], &[0, 0, 0, 0x40]);
        assert_eq!(elf_loader(&image), Err(UnpackError::NoStream("LZMA")));

        image.truncate(0x40 + 20);
        assert_eq!(elf_loader(&image), Err(UnpackError::Missing("program header")));
    }

    #[test]
    fn a_zimage_with_a_header_cut_short_is_missing() {
        let mut image = vec![0u8; ZIMAGE_MAGIC_OFFSET];
        image.extend_from_slice(&ZIMAGE_MAGIC);
        assert_eq!(unpack(&image), Err(UnpackError::Missing("zImage")));
    }

    #[test]
    fn a_tar_member_is_found_by_its_name() {
        let mut tar = vec![0u8; 512];
        tar[..19].copy_from_slice(b"sysupgrade-x/kernel");
        tar[124..135].copy_from_slice(b"00000000005");
        tar.extend_from_slice(b"hello");
        tar.resize(1024 + 1024, 0);
        assert_eq!(tar_member(&tar, "/kernel"), Some(&b"hello"[..]));
        assert_eq!(tar_member(&tar, "/root"), None);
    }

    #[test]
    fn an_image_of_no_known_container_is_refused() {
        assert_eq!(unpack(b"not firmware at all"), Err(UnpackError::Unrecognized));
        assert_eq!(unpack(&[]), Err(UnpackError::Unrecognized));
    }

    #[test]
    fn unpacking_any_bytes_never_panics() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            let _ = unpack(bytes);
            let _ = xz_decompress(bytes);
        });
    }
}
