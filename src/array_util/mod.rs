use std::{mem, ptr};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_u32a_le() {
        let mut dest = [0u32; 2];
        unsafe { align_to_u32a_le(&mut dest, &[0x78, 0x56, 0x34, 0x12, 0xFF, 0x00, 0xFF, 0x00]) }
        assert_eq!([0x1234_5678u32, 0x00FF_00FFu32], dest)
    }
}

/// Copies the ``source`` array to the ``dest`` array with respect to alignment and endianness. ``source`` must be at
/// least four times bigger than ``dest``, otherwise this function's behavior is undefined. Data from ``source``
/// will be treated as little endian integers
pub(crate) unsafe fn align_to_u32a_le(dest: &mut [u32], source: &[u8]) {
    assert!(source.len() >= dest.len() * 4);

    let mut byte_ptr: *const u8 = source.get_unchecked(0);
    let mut dword_ptr: *mut u32 = dest.get_unchecked_mut(0);

    for _ in 0..dest.len() {
        let mut current: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping(byte_ptr, &mut current as *mut _ as *mut u8, 4);
        *dword_ptr = u32::from_le(current);
        dword_ptr = dword_ptr.offset(1);
        byte_ptr = byte_ptr.offset(4);
    }
}

/// Copies the ``source`` array to the ``dest`` array with respect to alignment and endianness. ``source`` must be at
/// least four times bigger than ``dest``, otherwise this function's behavior is undefined. Data from ``source``
/// will be treated as big endian integers
pub(crate) unsafe fn align_to_u32a_be(dest: &mut [u32], source: &[u8]) {
    assert!(source.len() >= dest.len() * 4);

    let mut byte_ptr: *const u8 = source.get_unchecked(0);
    let mut dword_ptr: *mut u32 = dest.get_unchecked_mut(0);

    for _ in 0..dest.len() {
        let mut current: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping(byte_ptr, &mut current as *mut _ as *mut u8, 4);
        *dword_ptr = u32::from_be(current);
        dword_ptr = dword_ptr.offset(1);
        byte_ptr = byte_ptr.offset(4);
    }
}