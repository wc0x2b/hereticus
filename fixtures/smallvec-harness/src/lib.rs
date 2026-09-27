//! A C interface over `SmallVec` for three element types.
//!
//! Each element type is its own copy of every generic function, as in a real
//! Rust binary, so the fix to `insert_many` changes several functions and
//! leaves the rest the same.

#![no_std]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::slice;

use smallvec::SmallVec;

extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn realloc(pointer: *mut u8, size: usize) -> *mut u8;
    fn free(pointer: *mut u8);
    fn abort() -> !;
}

/// The largest alignment `malloc` gives on the targets built.
const MALLOC_ALIGNMENT: usize = 8;

/// Allocates from the C library the harness is loaded with.
struct Malloc;

unsafe impl GlobalAlloc for Malloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > MALLOC_ALIGNMENT {
            return core::ptr::null_mut();
        }
        malloc(layout.size())
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        free(pointer)
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if layout.align() > MALLOC_ALIGNMENT {
            return core::ptr::null_mut();
        }
        realloc(pointer, size)
    }
}

#[global_allocator]
static ALLOCATOR: Malloc = Malloc;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}

/// Read `length` items at `items`; a null pointer reads as none.
unsafe fn items<'a, T>(items: *const T, length: usize) -> &'a [T] {
    if items.is_null() { &[] } else { slice::from_raw_parts(items, length) }
}

/// Copy `vector` to `out`, as far as `capacity` allows, and give its length.
unsafe fn copy_out<T: Copy>(vector: &[T], out: *mut T, capacity: usize) -> usize {
    if !out.is_null() {
        let count = vector.len().min(capacity);
        slice::from_raw_parts_mut(out, count).copy_from_slice(&vector[..count]);
    }
    vector.len()
}

/// Export the operations for one element type and inline capacity.
macro_rules! export {
    ($item:ty, $inline:literal,
     $insert_many:ident, $insert_matching:ident, $retain:ident, $dedup:ident,
     $extend_reversed:ident, $remove:ident, $drain:ident) => {
        /// Insert `added` at `at`, which is clamped to the end.
        #[no_mangle]
        pub unsafe extern "C" fn $insert_many(
            base: *const $item, base_length: usize,
            at: usize,
            added: *const $item, added_length: usize,
            out: *mut $item, capacity: usize,
        ) -> usize {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            vector.insert_many(at.min(vector.len()), items(added, added_length).iter().copied());
            copy_out(&vector, out, capacity)
        }

        /// Insert the items of `added` that are not `skip` at `at`. The
        /// filter gives no lower bound, so every item goes past the hint.
        #[no_mangle]
        pub unsafe extern "C" fn $insert_matching(
            base: *const $item, base_length: usize,
            at: usize,
            added: *const $item, added_length: usize,
            skip: $item,
            out: *mut $item, capacity: usize,
        ) -> usize {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            let kept = items(added, added_length).iter().copied().filter(|item| *item != skip);
            vector.insert_many(at.min(vector.len()), kept);
            copy_out(&vector, out, capacity)
        }

        /// Keep the items below `limit`.
        #[no_mangle]
        pub unsafe extern "C" fn $retain(
            base: *const $item, base_length: usize,
            limit: $item,
            out: *mut $item, capacity: usize,
        ) -> usize {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            vector.retain(|item| *item < limit);
            copy_out(&vector, out, capacity)
        }

        /// Remove the repeats of each item that follow it.
        #[no_mangle]
        pub unsafe extern "C" fn $dedup(
            base: *const $item, base_length: usize,
            out: *mut $item, capacity: usize,
        ) -> usize {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            vector.dedup();
            copy_out(&vector, out, capacity)
        }

        /// Append `added` in reverse order.
        #[no_mangle]
        pub unsafe extern "C" fn $extend_reversed(
            base: *const $item, base_length: usize,
            added: *const $item, added_length: usize,
            out: *mut $item, capacity: usize,
        ) -> usize {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            vector.extend(items(added, added_length).iter().rev().copied());
            copy_out(&vector, out, capacity)
        }

        /// Remove the item at `at`, if there is one, and give it.
        #[no_mangle]
        pub unsafe extern "C" fn $remove(
            base: *const $item, base_length: usize,
            at: usize,
            out: *mut $item, capacity: usize,
            removed: *mut $item,
        ) -> usize {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            if at < vector.len() {
                let item = vector.remove(at);
                if !removed.is_null() {
                    *removed = item;
                }
            }
            copy_out(&vector, out, capacity)
        }

        /// Remove the items from `from` on, and give their sum.
        #[no_mangle]
        pub unsafe extern "C" fn $drain(
            base: *const $item, base_length: usize,
            from: usize,
        ) -> $item {
            let mut vector: SmallVec<[$item; $inline]> =
                SmallVec::from_slice(items(base, base_length));
            let from = from.min(vector.len());
            vector.drain(from..).fold(0, |sum: $item, item| sum.wrapping_add(item))
        }
    };
}

export!(u8, 8, u8_insert_many, u8_insert_matching, u8_retain, u8_dedup,
    u8_extend_reversed, u8_remove, u8_drain);
export!(u32, 4, u32_insert_many, u32_insert_matching, u32_retain, u32_dedup,
    u32_extend_reversed, u32_remove, u32_drain);
export!(u64, 2, u64_insert_many, u64_insert_matching, u64_retain, u64_dedup,
    u64_extend_reversed, u64_remove, u64_drain);
