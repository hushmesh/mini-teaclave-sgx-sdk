#![no_std]

use core::usize;

#[no_mangle]
pub extern "C" fn t_global_init_ecall(_id: u64, _path: *const u8, _len: usize) {}
