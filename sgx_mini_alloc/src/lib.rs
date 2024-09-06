#![no_std]

use core::alloc::GlobalAlloc;

extern "C" {
    // pub fn malloc(size: usize) -> *mut u8;
    pub fn memalign(align: usize, size: usize) -> *mut u8;
    pub fn free(p: *mut u8);
}

pub struct SgxMiniAlloc;

unsafe impl GlobalAlloc for SgxMiniAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe { memalign(layout.align(), layout.size()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe { free(ptr) }
    }
}
