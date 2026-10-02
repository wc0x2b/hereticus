//! Take the code out of a firmware image.
//!
//! A vendor ships a kernel compressed, behind a header, often with a small
//! decompressor in front of it. The comparison reads code, so the image must
//! be unpacked first: the decompressor, which runs as it is, and the kernel
//! it holds. These are the containers OpenWrt builds for the boards the tests
//! read:
//!
//! * a zImage, alone or in a FIT image: an ARM decompressor and an xz kernel
//! * a sysupgrade tar, whose `kernel` member is a zImage
//! * a uImage of an LZMA kernel
//! * a uImage of an lzma-loader: a MIPS decompressor and an LZMA kernel
//! * an ELF lzma-loader, as the ath79 boards boot
//! * a TP-Link v2 image: a header, then an LZMA kernel
//!
//! What a container says of where its parts load is kept, as a raw image
//! needs its base.

use std::io::Cursor;

/// The magic word of an ARM zImage, at offset 0x24 of it.
const ZIMAGE_MAGIC: [u8; 4] = 0x016f_2818_u32.to_le_bytes();
/// The magic of an xz stream.
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
/// The header OpenWrt's LZMA streams start with: the properties byte 0x6d,
/// `-lc1 -lp2`, then a dictionary of 8 MiB.
const LZMA_HEADER: &[u8] = b"\x6d\x00\x00\x80\x00";
/// The magic of a uImage, big endian.
const UIMAGE_MAGIC: [u8; 4] = [0x27, 0x05, 0x19, 0x56];
/// The length of a uImage header.
const UIMAGE_HEADER: usize = 64;
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

/// Unpack a firmware image.
pub fn unpack(image: &[u8]) -> Result<Unpacked, UnpackError> {
    if image.get(257..262) == Some(b"ustar") {
        let kernel = tar_member(image, "/kernel").ok_or(UnpackError::Missing("kernel"))?;
        let unpacked = zimage(kernel)?;
        return Ok(Unpacked { container: Container::SysupgradeTar, ..unpacked });
    }
    if image.starts_with(&UIMAGE_MAGIC) {
        return uimage(image);
    }
    if image.starts_with(b"\x7fELF\x01\x02") {
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
    let magic = find(image, &ZIMAGE_MAGIC, 0).ok_or(UnpackError::Missing("zImage"))?;
    let start = magic.checked_sub(0x24).ok_or(UnpackError::Missing("zImage"))?;
    let end_field = image.get(magic + 8..magic + 12).ok_or(UnpackError::Missing("zImage"))?;
    let length = u32::from_le_bytes(end_field.try_into().expect("four bytes")) as usize;
    let zimage = image.get(start..start + length).ok_or(UnpackError::Missing("zImage"))?;
    let (payload, kernel) = first_stream(zimage, 0, XZ_MAGIC, Stream::Xz)?;
    Ok(Unpacked {
        container: Container::ZImage,
        stub: Some(Part { bytes: zimage[..payload].to_vec(), load: None }),
        kernel: Part { bytes: kernel, load: None },
    })
}

/// A uImage holds an LZMA kernel, or, uncompressed, an lzma-loader: a
/// decompressor with an LZMA kernel inside it.
fn uimage(image: &[u8]) -> Result<Unpacked, UnpackError> {
    /// The compression byte of a uImage header that means LZMA.
    const LZMA: u8 = 3;
    let word = |offset: usize| -> Option<u32> {
        Some(u32::from_be_bytes(image.get(offset..offset + 4)?.try_into().ok()?))
    };
    let size = word(12).ok_or(UnpackError::Missing("uImage header"))? as usize;
    let load = word(16).map(u64::from);
    let body = image
        .get(UIMAGE_HEADER..UIMAGE_HEADER + size)
        .ok_or(UnpackError::Missing("uImage body"))?;
    let (payload, kernel) = first_stream(body, 0, LZMA_HEADER, Stream::Lzma)?;
    if image[31] == LZMA {
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
    let word = |offset: usize| -> Option<u32> {
        Some(u32::from_be_bytes(image.get(offset..offset + 4)?.try_into().ok()?))
    };
    let header = word(28).ok_or(UnpackError::Missing("program header"))? as usize;
    let missing = UnpackError::Missing("program header");
    let (offset, address, size) = (
        word(header + 4).ok_or(missing.clone())? as usize,
        word(header + 8).ok_or(missing.clone())?,
        word(header + 16).ok_or(missing)? as usize,
    );
    let loaded = image.get(offset..offset + size).ok_or(UnpackError::Missing("loader"))?;
    let (payload, kernel) = first_stream(loaded, 0, LZMA_HEADER, Stream::Lzma)?;
    Ok(Unpacked {
        container: Container::ElfLoader,
        stub: Some(Part { bytes: loaded[..payload].to_vec(), load: Some(address.into()) }),
        kernel: Part { bytes: kernel, load: None },
    })
}

/// A TP-Link v2 image: a header, then an LZMA kernel up to the root
/// filesystem.
fn tplink_v2(image: &[u8]) -> Result<Unpacked, UnpackError> {
    let rootfs = find(image, SQUASHFS_MAGIC, TPLINK_V2_HEADER)
        .ok_or(UnpackError::Missing("root filesystem"))?;
    let (_, kernel) = first_stream(&image[..rootfs], TPLINK_V2_HEADER, LZMA_HEADER, Stream::Lzma)?;
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
    /// The `.xz` format, as an ARM zImage holds.
    Xz,
}

/// The first stream with `magic` at or after `start` that decodes, by its
/// offset and what it decodes to.
///
/// The magic alone is not enough: a decompressor holds its own format's
/// magic as a constant, so the first match can sit inside the stub. The
/// ARM stub of the tests does exactly this, 231 bytes before its payload.
fn first_stream(
    data: &[u8],
    start: usize,
    magic: &[u8],
    kind: Stream,
) -> Result<(usize, Vec<u8>), UnpackError> {
    let mut from = start;
    while let Some(offset) = find(data, magic, from) {
        let decoded = match kind {
            Stream::Lzma => {
                let mut out = Vec::new();
                lzma_rs::lzma_decompress(&mut Cursor::new(&data[offset..]), &mut out)
                    .ok()
                    .map(|()| out)
            }
            Stream::Xz => xz_decompress(&data[offset..]),
        };
        if let Some(decoded) = decoded {
            return Ok((offset, decoded));
        }
        from = offset + 1;
    }
    Err(UnpackError::NoStream(match kind {
        Stream::Lzma => "LZMA",
        Stream::Xz => "xz",
    }))
}

/// Decode the first xz stream of `data`.
///
/// `lzma-rs` decodes the LZMA2 inside but no branch filter, and the kernel
/// in an ARM zImage is filtered for ARM: each `bl` holds an absolute target,
/// which compresses better. So the blocks are read here, their LZMA2 decoded,
/// and the ARM filter undone. Other filters are refused.
fn xz_decompress(data: &[u8]) -> Option<Vec<u8>> {
    /// The filter IDs of the xz format this reads.
    const ARM: u64 = 0x07;
    const LZMA2: u64 = 0x21;

    if !data.starts_with(XZ_MAGIC) {
        return None;
    }
    let check_size = match data.get(7)? & 0x0f {
        0x00 => 0,
        0x01 => 4,
        0x04 => 8,
        0x0a => 32,
        _ => return None,
    };
    let mut at = 12;
    let mut out = Vec::new();
    loop {
        let size_byte = *data.get(at)?;
        // A zero byte opens the index, which ends the blocks.
        if size_byte == 0 {
            return Some(out);
        }
        let header_size = (usize::from(size_byte) + 1) * 4;
        let header = data.get(at..at + header_size)?;
        let flags = header[1];
        let mut field = Cursor::new(&header[2..header_size - 4]);
        if flags & 0x40 != 0 {
            varint(&mut field)?;
        }
        if flags & 0x80 != 0 {
            varint(&mut field)?;
        }
        let mut arm = false;
        for _ in 0..=(flags & 0x03) {
            let id = varint(&mut field)?;
            let properties = varint(&mut field)?;
            field.set_position(field.position() + properties);
            match id {
                ARM if properties == 0 => arm = true,
                LZMA2 => {}
                _ => return None,
            }
        }

        let start = at + header_size;
        let mut input = Cursor::new(data.get(start..)?);
        let mut block = Vec::new();
        lzma_rs::lzma2_decompress(&mut input, &mut block).ok()?;
        if arm {
            undo_arm_filter(&mut block);
        }
        out.extend_from_slice(&block);

        let compressed = usize::try_from(input.position()).ok()?;
        at = start + compressed.next_multiple_of(4) + check_size;
    }
}

/// Undo the xz ARM filter: each `bl` holds its target as an address from
/// the start of the data, and the filter takes the instruction's own
/// address back out.
fn undo_arm_filter(data: &mut [u8]) {
    for at in (0..data.len().saturating_sub(3)).step_by(4) {
        if data[at + 3] != 0xeb {
            continue;
        }
        let absolute =
            (u32::from(data[at + 2]) << 16 | u32::from(data[at + 1]) << 8 | u32::from(data[at]))
                << 2;
        let relative = absolute.wrapping_sub(at as u32 + 8) >> 2;
        data[at] = relative as u8;
        data[at + 1] = (relative >> 8) as u8;
        data[at + 2] = (relative >> 16) as u8;
    }
}

/// Read one variable-length integer of the xz format.
fn varint(input: &mut Cursor<&[u8]>) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..63).step_by(7) {
        let position = usize::try_from(input.position()).ok()?;
        let byte = *input.get_ref().get(position)?;
        input.set_position(input.position() + 1);
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The bytes of the first member of a tar whose name ends with `suffix`.
fn tar_member<'a>(tar: &'a [u8], suffix: &str) -> Option<&'a [u8]> {
    /// The length of a tar header, and of each block.
    const BLOCK: usize = 512;
    let mut at = 0;
    while let Some(header) = tar.get(at..at + BLOCK) {
        if header.iter().all(|&byte| byte == 0) {
            return None;
        }
        let name_end = header[..100].iter().position(|&byte| byte == 0).unwrap_or(100);
        let name = core::str::from_utf8(&header[..name_end]).ok()?;
        let size_field = core::str::from_utf8(&header[124..136]).ok()?;
        let size =
            usize::from_str_radix(size_field.trim_matches(|c: char| c == '\0' || c == ' '), 8)
                .ok()?;
        let body = at + BLOCK;
        if name.ends_with(suffix) {
            return tar.get(body..body + size);
        }
        at = body + size.next_multiple_of(BLOCK);
    }
    None
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
        undo_arm_filter(&mut data);
        assert_eq!(data[8..], [0x3e, 0x00, 0x00, 0xeb]);
        // A word that is no `bl` stays.
        let mut other = vec![0x42, 0x00, 0x00, 0xea];
        undo_arm_filter(&mut other);
        assert_eq!(other, [0x42, 0x00, 0x00, 0xea]);
    }

    #[test]
    fn a_varint_reads_seven_bits_a_byte() {
        assert_eq!(varint(&mut Cursor::new(&[0x21][..])), Some(0x21));
        assert_eq!(varint(&mut Cursor::new(&[0x80, 0x01][..])), Some(0x80));
        assert_eq!(varint(&mut Cursor::new(&[0x80][..])), None, "cut short");
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
