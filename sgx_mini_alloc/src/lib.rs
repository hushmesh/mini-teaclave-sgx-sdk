#![no_std]

use core::alloc::GlobalAlloc;
use core::ptr::write_bytes;

use sgx_mini_types::sgx_aligned_free;
use sgx_mini_types::sgx_aligned_malloc;

pub struct SgxMiniAlloc;

unsafe impl GlobalAlloc for SgxMiniAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe {
            sgx_aligned_malloc(layout.size(), layout.align(), core::ptr::null(), 0) as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe {
            write_bytes(ptr, 0u8, layout.size());
            sgx_aligned_free(ptr as *mut core::ffi::c_void);
        }
    }
}
